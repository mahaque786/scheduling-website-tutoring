-- =============================================================================
-- Supabase schema for the scheduling / tutoring booking site (index.html)
-- -----------------------------------------------------------------------------
-- This script is idempotent and can be run against a Supabase Postgres
-- database (e.g. via the SQL editor or `supabase db execute`).
--
-- It creates:
--   * Tables used by the page:
--       - service_types  (read by the page via PostgREST)
--       - locations      (read by the page via PostgREST)
--       - location_hours (used by get_available_slots to know when a location
--                         is open; not read directly by the page)
--       - bookings       (written by create_booking; not read directly by the
--                         page)
--   * Row-Level Security policies that:
--       - allow the `anon` role to SELECT active rows from service_types and
--         locations (the page reads these directly), and
--       - do NOT expose bookings to the `anon` role directly; writes happen
--         only through the create_booking RPC, which runs as SECURITY DEFINER.
--   * Two RPC functions, with the EXACT parameter names the page uses:
--       - get_available_slots(
--             p_location_id uuid,
--             p_service_type_id uuid,
--             p_date date,
--             p_timezone text,
--             p_slot_interval_minutes int
--         )
--       - create_booking(
--             p_service_type_id uuid,
--             p_location_id uuid,
--             p_client_name text,
--             p_client_email text,
--             p_client_phone text,
--             p_notes text,
--             p_starts_at timestamptz,
--             p_timezone text
--         )
--     Both are SECURITY DEFINER so they can work regardless of the caller's
--     RLS context, and EXECUTE is granted to the `anon` role.
-- =============================================================================

-- Required for gen_random_uuid() (available by default in Supabase).
create extension if not exists "pgcrypto";

-- -----------------------------------------------------------------------------
-- Tables
-- -----------------------------------------------------------------------------

create table if not exists public.service_types (
    id               uuid primary key default gen_random_uuid(),
    name             text not null,
    duration_minutes int  not null check (duration_minutes > 0),
    active           boolean not null default true,
    created_at       timestamptz not null default now()
);

create table if not exists public.locations (
    id         uuid primary key default gen_random_uuid(),
    name       text not null,
    address    text,
    timezone   text not null default 'America/Chicago',
    active     boolean not null default true,
    created_at timestamptz not null default now()
);

-- Operating hours per location and day-of-week (0 = Sunday .. 6 = Saturday),
-- consumed by get_available_slots to generate candidate slots.
create table if not exists public.location_hours (
    id          uuid primary key default gen_random_uuid(),
    location_id uuid not null references public.locations(id) on delete cascade,
    day_of_week int  not null check (day_of_week between 0 and 6),
    open_time   time not null,
    close_time  time not null,
    check (close_time > open_time),
    unique (location_id, day_of_week)
);

create table if not exists public.bookings (
    id              uuid primary key default gen_random_uuid(),
    service_type_id uuid not null references public.service_types(id),
    location_id     uuid not null references public.locations(id),
    client_name     text not null,
    client_email    text not null,
    client_phone    text not null,
    notes           text,
    starts_at       timestamptz not null,
    ends_at         timestamptz not null,
    timezone        text not null,
    status          text not null default 'confirmed'
                      check (status in ('confirmed', 'cancelled')),
    created_at      timestamptz not null default now(),
    check (ends_at > starts_at)
);

-- Prevent double-booking the same location at the same time (only for
-- non-cancelled bookings).
create unique index if not exists bookings_location_start_unique
    on public.bookings (location_id, starts_at)
    where status = 'confirmed';

create index if not exists bookings_location_starts_at_idx
    on public.bookings (location_id, starts_at);

-- -----------------------------------------------------------------------------
-- Row-Level Security
-- -----------------------------------------------------------------------------

alter table public.service_types  enable row level security;
alter table public.locations      enable row level security;
alter table public.location_hours enable row level security;
alter table public.bookings       enable row level security;

-- The page does:
--   supabase.from('service_types').select('id, name, duration_minutes').eq('active', true)
--   supabase.from('locations').select('id, name, address').eq('active', true)
-- so anon must be able to read active rows.

drop policy if exists "service_types readable (active)" on public.service_types;
create policy "service_types readable (active)"
    on public.service_types
    for select
    to anon, authenticated
    using (active = true);

drop policy if exists "locations readable (active)" on public.locations;
create policy "locations readable (active)"
    on public.locations
    for select
    to anon, authenticated
    using (active = true);

-- location_hours and bookings are NOT read/written directly by the page.
-- They are accessed only through the SECURITY DEFINER RPCs below, which
-- bypass RLS. We therefore do not create any permissive policies for anon,
-- which means direct PostgREST access is effectively denied.

-- -----------------------------------------------------------------------------
-- Baseline table privileges for the anon role.
-- RLS still governs which rows are visible; these grants just allow the
-- SELECT/INSERT verbs to reach the RLS layer. Bookings remain unreachable
-- directly because no RLS policy matches.
-- -----------------------------------------------------------------------------

grant usage on schema public to anon, authenticated;
grant select on public.service_types to anon, authenticated;
grant select on public.locations     to anon, authenticated;

-- =============================================================================
-- RPC: get_available_slots
-- -----------------------------------------------------------------------------
-- Returns a list of { slot_start timestamptz } for the given location, service
-- and local date. Honors the location_hours for the day, subtracts already-
-- booked intervals, and walks the day in p_slot_interval_minutes increments.
-- =============================================================================

create or replace function public.get_available_slots(
    p_location_id           uuid,
    p_service_type_id       uuid,
    p_date                  date,
    p_timezone              text,
    p_slot_interval_minutes int
)
returns table (slot_start timestamptz)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_duration_minutes int;
    v_open_time        time;
    v_close_time       time;
    v_day_of_week      int;
    v_day_start        timestamptz;
    v_day_end          timestamptz;
    v_candidate        timestamptz;
    v_candidate_end    timestamptz;
begin
    if p_location_id is null
       or p_service_type_id is null
       or p_date is null
       or p_timezone is null
       or p_slot_interval_minutes is null
       or p_slot_interval_minutes <= 0 then
        return;
    end if;

    -- Service must exist and be active.
    select duration_minutes
      into v_duration_minutes
      from public.service_types
     where id = p_service_type_id
       and active = true;

    if v_duration_minutes is null then
        return;
    end if;

    -- Location must exist and be active.
    if not exists (
        select 1 from public.locations
         where id = p_location_id and active = true
    ) then
        return;
    end if;

    -- Day-of-week in the caller's timezone (0 = Sunday .. 6 = Saturday).
    v_day_of_week := extract(
        dow from (p_date::timestamp at time zone p_timezone)
    )::int;

    select open_time, close_time
      into v_open_time, v_close_time
      from public.location_hours
     where location_id = p_location_id
       and day_of_week = v_day_of_week;

    -- Closed that day -> no slots.
    if v_open_time is null then
        return;
    end if;

    -- Convert the local open/close times on p_date into absolute timestamps.
    v_day_start := (p_date + v_open_time)  at time zone p_timezone;
    v_day_end   := (p_date + v_close_time) at time zone p_timezone;

    v_candidate := v_day_start;

    while v_candidate + make_interval(mins => v_duration_minutes) <= v_day_end loop
        v_candidate_end := v_candidate + make_interval(mins => v_duration_minutes);

        -- Only expose future slots.
        if v_candidate > now()
           and not exists (
               select 1
                 from public.bookings b
                where b.location_id = p_location_id
                  and b.status = 'confirmed'
                  and b.starts_at < v_candidate_end
                  and b.ends_at   > v_candidate
           )
        then
            slot_start := v_candidate;
            return next;
        end if;

        v_candidate := v_candidate + make_interval(mins => p_slot_interval_minutes);
    end loop;

    return;
end;
$$;

-- =============================================================================
-- RPC: create_booking
-- -----------------------------------------------------------------------------
-- Inserts a booking after validating the slot is still available. Returns the
-- newly created booking row.
-- =============================================================================

create or replace function public.create_booking(
    p_service_type_id uuid,
    p_location_id     uuid,
    p_client_name     text,
    p_client_email    text,
    p_client_phone    text,
    p_notes           text,
    p_starts_at       timestamptz,
    p_timezone        text
)
returns public.bookings
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_duration_minutes int;
    v_ends_at          timestamptz;
    v_row              public.bookings;
begin
    if p_service_type_id is null
       or p_location_id is null
       or p_starts_at is null
       or p_timezone is null
       or coalesce(trim(p_client_name),  '') = ''
       or coalesce(trim(p_client_email), '') = ''
       or coalesce(trim(p_client_phone), '') = '' then
        raise exception 'Missing required booking fields';
    end if;

    if p_starts_at <= now() then
        raise exception 'Cannot book a time in the past';
    end if;

    select duration_minutes
      into v_duration_minutes
      from public.service_types
     where id = p_service_type_id
       and active = true;

    if v_duration_minutes is null then
        raise exception 'Invalid or inactive service type';
    end if;

    if not exists (
        select 1 from public.locations
         where id = p_location_id and active = true
    ) then
        raise exception 'Invalid or inactive location';
    end if;

    v_ends_at := p_starts_at + make_interval(mins => v_duration_minutes);

    -- Conflict check against existing confirmed bookings at this location.
    if exists (
        select 1
          from public.bookings b
         where b.location_id = p_location_id
           and b.status = 'confirmed'
           and b.starts_at < v_ends_at
           and b.ends_at   > p_starts_at
    ) then
        raise exception 'Selected time slot is no longer available';
    end if;

    insert into public.bookings (
        service_type_id,
        location_id,
        client_name,
        client_email,
        client_phone,
        notes,
        starts_at,
        ends_at,
        timezone
    )
    values (
        p_service_type_id,
        p_location_id,
        trim(p_client_name),
        trim(p_client_email),
        trim(p_client_phone),
        nullif(trim(coalesce(p_notes, '')), ''),
        p_starts_at,
        v_ends_at,
        p_timezone
    )
    returning * into v_row;

    return v_row;
end;
$$;

-- -----------------------------------------------------------------------------
-- Function ownership & EXECUTE grants
-- -----------------------------------------------------------------------------
-- SECURITY DEFINER functions execute with the privileges of their owner.
-- In Supabase, `postgres` is the standard owner and already has full access
-- to tables in the `public` schema. We lock down the default PUBLIC grant
-- and explicitly grant EXECUTE to `anon` (and `authenticated` for parity).

revoke all on function public.get_available_slots(uuid, uuid, date, text, int) from public;
revoke all on function public.create_booking(uuid, uuid, text, text, text, text, timestamptz, text) from public;

grant execute on function public.get_available_slots(uuid, uuid, date, text, int)
    to anon, authenticated;

grant execute on function public.create_booking(uuid, uuid, text, text, text, text, timestamptz, text)
    to anon, authenticated;
