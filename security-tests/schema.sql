-- Copy of the shared Supabase project's public schema, access rules (RLS),
-- triggers and grants, read from the live catalog on 2026-10-16.
-- Used ONLY to load a throwaway local database for the attack tests.
-- Never run this against the real project.

create table public.habits (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  name text not null check (char_length(name) >= 1 and char_length(name) <= 60),
  days smallint[] not null default '{0,1,2,3,4,5,6}',
  archived boolean not null default false,
  created_at timestamptz not null default now(),
  color smallint check (color is null or color >= 0 and color <= 7),
  remind_time time,
  last_reminded date,
  target_per_week smallint check (target_per_week is null or target_per_week >= 1 and target_per_week <= 6),
  sort_order integer not null default 0
);
create index habits_user_idx on public.habits (user_id);

create table public.check_ins (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  habit_id uuid not null references public.habits(id) on delete cascade,
  day date not null,
  status text not null default 'done' check (status = any (array['done','skipped'])),
  note text check (note is null or char_length(note) <= 200),
  created_at timestamptz not null default now(),
  unique (habit_id, day)
);
create index check_ins_user_day_idx on public.check_ins (user_id, day);

create table public.push_subscriptions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  endpoint text not null unique check (char_length(endpoint) >= 10 and char_length(endpoint) <= 2000),
  p256dh text not null,
  auth text not null,
  tz text not null default 'UTC',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint push_endpoint_host check (endpoint ~ '^https://(fcm\.googleapis\.com|updates\.push\.services\.mozilla\.com|[a-z0-9.-]+\.push\.apple\.com|[a-z0-9.-]+\.notify\.windows\.com)/'),
  constraint push_field_sizes check (char_length(p256dh) <= 100 and char_length(auth) <= 50 and char_length(tz) <= 64)
);
create index push_subscriptions_user_idx on public.push_subscriptions (user_id);

create table public.waitlist (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  email text not null check (char_length(email) >= 5 and char_length(email) <= 254 and email ~* '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]{2,}$'),
  trade text not null check (trade = any (array['hvac','pest','lawn','pool','gutter','other'])),
  tracking text not null check (tracking = any (array['spreadsheet','notebook','memory','software','nothing'])),
  source text check (source is null or char_length(source) <= 40 and source ~ '^[a-z0-9_-]+$'),
  page text not null default 'renewals' check (page ~ '^[a-z0-9_-]{1,30}$'),
  wants text check (wants is null or wants = any (array['due_list','nearby','weather','winback','import']))
);
create unique index waitlist_email_page_uidx on public.waitlist (lower(email), page);
create index waitlist_created_at_idx on public.waitlist (created_at);

alter table public.habits enable row level security;
alter table public.check_ins enable row level security;
alter table public.push_subscriptions enable row level security;
alter table public.waitlist enable row level security;

create policy "Users manage their own habits" on public.habits for all to authenticated
  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "Users manage their own check-ins" on public.check_ins for all to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id and exists (select 1 from public.habits h where h.id = check_ins.habit_id and h.user_id = (select auth.uid())));
create policy "Users manage their own push subscriptions" on public.push_subscriptions for all to authenticated
  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "Anyone can join the waitlist" on public.waitlist for insert to anon, authenticated with check (true);

create function public.enforce_limits() returns trigger language plpgsql set search_path = public, pg_catalog as $$
begin
  if tg_table_name in ('habits','push_subscriptions') and tg_op = 'INSERT' then
    perform pg_advisory_xact_lock(hashtext(tg_table_name || new.user_id::text));
  end if;
  if tg_table_name = 'habits' and tg_op = 'INSERT' then
    if (select count(*) from public.habits where user_id = new.user_id) >= 60 then
      raise exception 'Limit reached: at most 60 habits per account (archived ones count).' using errcode = '23514';
    end if;
  elsif tg_table_name = 'push_subscriptions' and tg_op = 'INSERT' then
    if (select count(*) from public.push_subscriptions where user_id = new.user_id) >= 10 then
      raise exception 'Limit reached: at most 10 devices for notifications.' using errcode = '23514';
    end if;
  elsif tg_table_name = 'check_ins' then
    if new.day < current_date - 3660 or new.day > current_date + 2 then
      raise exception 'That date is outside the allowed range.' using errcode = '23514';
    end if;
  end if;
  return new;
end; $$;

create function public.waitlist_cap() returns trigger language plpgsql security definer set search_path = public, pg_catalog as $$
begin
  if (select count(*) from public.waitlist) >= 5000 then
    raise exception 'Waitlist is full.' using errcode = '23514';
  end if;
  return new;
end; $$;

create function public.waitlist_rate_limit() returns trigger language plpgsql security definer set search_path = '' as $$
begin
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('public.waitlist_rate_limit'));
  if (select count(*) from public.waitlist where created_at > pg_catalog.now() - interval '1 minute') >= 20
     or (select count(*) from public.waitlist where created_at > pg_catalog.now() - interval '1 hour') >= 200 then
    raise sqlstate 'PGRST' using
      message = '{"code":"WL429","message":"Too many sign-ups right now. Try again in a few minutes."}',
      detail = '{"status":429,"headers":{"Retry-After":"60"}}';
  end if;
  return new;
end; $$;

create function public.due_reminders() returns table(habit_id uuid, user_id uuid, name text, local_day date)
language sql stable security definer set search_path = public, pg_catalog as $$
  with latest as (
    select distinct on (s.user_id) s.user_id, s.tz from public.push_subscriptions s
    join pg_catalog.pg_timezone_names z on z.name = s.tz order by s.user_id, s.updated_at desc
  ), t as (select l.user_id, (now() at time zone l.tz) as local_now from latest l)
  select h.id, h.user_id, h.name, t.local_now::date from public.habits h join t on t.user_id = h.user_id
  where not h.archived and h.remind_time is not null
    and extract(dow from t.local_now)::smallint = any (h.days)
    and (t.local_now::time - h.remind_time) >= interval '0' and (t.local_now::time - h.remind_time) < interval '3 hours'
    and (h.last_reminded is null or h.last_reminded < t.local_now::date)
    and not exists (select 1 from public.check_ins c where c.habit_id = h.id and c.day = t.local_now::date);
$$;

create trigger habits_limits before insert on public.habits for each row execute function public.enforce_limits();
create trigger push_subscriptions_limits before insert on public.push_subscriptions for each row execute function public.enforce_limits();
create trigger check_ins_limits before insert or update of day on public.check_ins for each row execute function public.enforce_limits();
create trigger waitlist_cap_trg before insert on public.waitlist for each row execute function public.waitlist_cap();
create trigger waitlist_rate_limit_trg before insert on public.waitlist for each row execute function public.waitlist_rate_limit();

-- Grants exactly as they are live
revoke all on public.habits, public.check_ins, public.push_subscriptions, public.waitlist from anon, authenticated;
grant references, trigger, truncate on public.habits, public.check_ins, public.push_subscriptions to anon;
grant select, insert, update, delete, references, trigger, truncate on public.habits, public.check_ins, public.push_subscriptions to authenticated;
grant insert on public.waitlist to anon, authenticated;
revoke execute on function public.due_reminders(), public.waitlist_cap(), public.waitlist_rate_limit() from public, anon, authenticated;
grant all on all tables in schema public to service_role;
