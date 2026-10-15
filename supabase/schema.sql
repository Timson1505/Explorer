-- Budapest Explorer: run once in Supabase SQL Editor. All public-schema tables have RLS.
create extension if not exists pgcrypto;

create type public.user_role as enum ('guest', 'admin');
create type public.tour_type as enum ('walking', 'cycling');
create type public.booking_status as enum ('confirmed', 'cancelled');
create type public.departure_status as enum ('open', 'closed', 'cancelled');

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text,
  role public.user_role not null default 'guest',
  created_at timestamptz not null default now()
);
create table public.tours (
  id uuid primary key default gen_random_uuid(), slug text not null unique, title text not null,
  summary text not null, type public.tour_type not null, duration_minutes integer not null check(duration_minutes > 0),
  price_eur numeric(10,2) not null check(price_eur >= 0), cover_image text, is_published boolean not null default false,
  created_at timestamptz not null default now()
);
create table public.departures (
  id uuid primary key default gen_random_uuid(), tour_id uuid not null references public.tours(id) on delete cascade,
  starts_at timestamptz not null, capacity integer not null check(capacity between 1 and 30),
  booked_count integer not null default 0 check(booked_count >= 0 and booked_count <= capacity),
  status public.departure_status not null default 'open', created_at timestamptz not null default now(), unique(tour_id, starts_at)
);
create table public.bookings (
  id uuid primary key default gen_random_uuid(), user_id uuid not null references public.profiles(id) on delete restrict,
  departure_id uuid not null references public.departures(id) on delete restrict, guests integer not null check(guests between 1 and 14),
  guest_note text check(char_length(guest_note) <= 500), status public.booking_status not null default 'confirmed',
  created_at timestamptz not null default now(), cancelled_at timestamptz
);
create table public.reviews (
  id uuid primary key default gen_random_uuid(), booking_id uuid not null unique references public.bookings(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete restrict, tour_id uuid not null references public.tours(id) on delete restrict,
  rating integer not null check(rating between 1 and 5), body text not null check(char_length(body) between 10 and 1000),
  is_published boolean not null default false, created_at timestamptz not null default now()
);
create table public.activity_log (
  id bigint generated always as identity primary key, actor_id uuid references auth.users(id) on delete set null,
  action text not null, entity_type text not null, entity_id uuid, details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
create index departures_open_starts_idx on public.departures(starts_at) where status = 'open';
create index bookings_user_idx on public.bookings(user_id, created_at desc);
create index activity_log_created_idx on public.activity_log(created_at desc);

alter table public.profiles enable row level security;
alter table public.tours enable row level security;
alter table public.departures enable row level security;
alter table public.bookings enable row level security;
alter table public.reviews enable row level security;
alter table public.activity_log enable row level security;

-- Explicit Data API access; RLS below decides which rows each role can see.
grant usage on schema public to anon, authenticated;
grant select on public.tours, public.departures, public.reviews to anon, authenticated;
grant select on public.profiles, public.bookings, public.activity_log to authenticated;
grant insert on public.reviews to authenticated;

-- This narrowly scoped helper is required for policies. It never trusts editable user metadata.
create function public.is_admin() returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id = (select auth.uid()) and role = 'admin');
$$;
revoke all on function public.is_admin() from public;
grant execute on function public.is_admin() to authenticated;

create policy "profiles: own record" on public.profiles for select to authenticated using (id = (select auth.uid()));
create policy "profiles: admin reads all" on public.profiles for select to authenticated using ((select public.is_admin()));
create policy "tours: public read" on public.tours for select to anon, authenticated using (is_published or (select public.is_admin()));
create policy "tours: admin manage" on public.tours for all to authenticated using ((select public.is_admin())) with check ((select public.is_admin()));
create policy "departures: public read" on public.departures for select to anon, authenticated using (status = 'open' or (select public.is_admin()));
create policy "departures: admin manage" on public.departures for all to authenticated using ((select public.is_admin())) with check ((select public.is_admin()));
create policy "bookings: guest reads own" on public.bookings for select to authenticated using (user_id = (select auth.uid()));
create policy "bookings: admin reads all" on public.bookings for select to authenticated using ((select public.is_admin()));
create policy "reviews: public published read" on public.reviews for select to anon, authenticated using (is_published or user_id = (select auth.uid()) or (select public.is_admin()));
create policy "reviews: guest creates own" on public.reviews for insert to authenticated with check (user_id = (select auth.uid()));
create policy "reviews: admin manages" on public.reviews for all to authenticated using ((select public.is_admin())) with check ((select public.is_admin()));
create policy "audit: admin reads" on public.activity_log for select to authenticated using ((select public.is_admin()));

create function public.handle_new_user() returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles(id, display_name) values (new.id, coalesce(new.raw_user_meta_data ->> 'display_name', split_part(new.email, '@', 1)));
  insert into public.activity_log(actor_id, action, entity_type, entity_id, details) values (new.id, 'registered', 'profile', new.id, jsonb_build_object('email', new.email));
  return new;
end; $$;
create trigger on_auth_user_created after insert on auth.users for each row execute procedure public.handle_new_user();

-- Atomic booking prevents two guests from taking the same final place.
create function public.create_booking(p_departure_id uuid, p_guests integer, p_guest_note text default null) returns uuid
language plpgsql security definer set search_path = public as $$
declare v_booking uuid; v_departure public.departures;
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  if p_guests not between 1 and 14 then raise exception 'Guests must be between 1 and 14'; end if;
  select * into v_departure from public.departures where id = p_departure_id for update;
  if not found or v_departure.status <> 'open' or v_departure.starts_at <= now() then raise exception 'This departure is unavailable'; end if;
  if v_departure.booked_count + p_guests > v_departure.capacity then raise exception 'Not enough places remaining'; end if;
  insert into public.bookings(user_id, departure_id, guests, guest_note) values (auth.uid(), p_departure_id, p_guests, p_guest_note) returning id into v_booking;
  update public.departures set booked_count = booked_count + p_guests where id = p_departure_id;
  insert into public.activity_log(actor_id,action,entity_type,entity_id,details) values(auth.uid(),'booked','booking',v_booking,jsonb_build_object('departure_id',p_departure_id,'guests',p_guests));
  return v_booking;
end; $$;
create function public.cancel_booking(p_booking_id uuid) returns void language plpgsql security definer set search_path = public as $$
declare v_booking public.bookings;
begin
  select * into v_booking from public.bookings where id=p_booking_id for update;
  if not found then raise exception 'Booking not found'; end if;
  if v_booking.user_id <> auth.uid() and not public.is_admin() then raise exception 'Not authorized'; end if;
  if v_booking.status = 'cancelled' then raise exception 'Booking is already cancelled'; end if;
  update public.bookings set status='cancelled', cancelled_at=now() where id=p_booking_id;
  update public.departures set booked_count=booked_count-v_booking.guests where id=v_booking.departure_id;
  insert into public.activity_log(actor_id,action,entity_type,entity_id,details) values(auth.uid(),'cancelled','booking',p_booking_id,jsonb_build_object('guests',v_booking.guests));
end; $$;
revoke all on function public.create_booking(uuid,integer,text) from public;
revoke all on function public.cancel_booking(uuid) from public;
grant execute on function public.create_booking(uuid,integer,text), public.cancel_booking(uuid) to authenticated;

-- Set one approved account after registration (replace the email):
-- update public.profiles set role = 'admin' where id = (select id from auth.users where email = 'owner@example.com');

insert into public.tours(slug,title,summary,type,duration_minutes,price_eur,cover_image,is_published) values
('budapest-highlights-walk','Budapest Highlights Walking Tour','A first-day walk through Pest’s grand boulevards, riverbanks and iconic landmarks.','walking',150,29,'https://images.unsplash.com/photo-1551867633-194f125bddfa?auto=format&fit=crop&w=900&q=80',true),
('danube-cycling-adventure','Danube Cycling Adventure','Ride both banks of the Danube and discover Budapest’s landmark views by bike.','cycling',180,39,'https://images.unsplash.com/photo-1531058020387-3be344556be6?auto=format&fit=crop&w=900&q=80',true),
('castle-district-walk','Buda Castle District Walk','Follow cobbled lanes, royal courtyards and sweeping views across the Danube.','walking',180,35,'https://images.unsplash.com/photo-1585421514738-01798e348b17?auto=format&fit=crop&w=900&q=80',true);
insert into public.departures(tour_id,starts_at,capacity) select id, now() + interval '3 days', 14 from public.tours;
insert into public.departures(tour_id,starts_at,capacity) select id, now() + interval '10 days', 14 from public.tours;
