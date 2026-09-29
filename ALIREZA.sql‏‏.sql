create extension if not exists pgcrypto;

create table if not exists public.reviews (
  id          uuid primary key default gen_random_uuid(),
  first_name  text not null check (char_length(first_name) between 2 and 30),
  last_name   text not null check (char_length(last_name)  between 1 and 30),
  email       text not null check (
                char_length(email) <= 80
                and email ~* '^[^@\s]+@[^@\s]+\.[^@\s]+$'
              ),
  body        text not null check (char_length(body) between 10 and 500),
  approved    boolean not null default false,
  created_at  timestamptz not null default now()
);

create index if not exists idx_reviews_approved_created
  on public.reviews (approved, created_at desc);

alter table public.reviews enable row level security;

revoke all on public.reviews from anon, authenticated;
revoke all on public.reviews from public;

grant insert (first_name, last_name, email, body)
  on public.reviews to anon;

drop policy if exists "anyone can submit pending review" on public.reviews;
create policy "anyone can submit pending review"
  on public.reviews
  for insert
  to anon
  with check (
    approved = false
    and char_length(first_name) between 2 and 30
    and char_length(last_name) between 1 and 30
    and char_length(email) <= 80
    and char_length(body) between 10 and 500
  );

grant select, insert, update, delete on public.reviews to authenticated;

drop policy if exists "admin select" on public.reviews;
create policy "admin select" on public.reviews
  for select to authenticated
  using ((auth.jwt() ->> 'email') = 'YOUR_ADMIN_EMAIL@example.com');

drop policy if exists "admin insert" on public.reviews;
create policy "admin insert" on public.reviews
  for insert to authenticated
  with check ((auth.jwt() ->> 'email') = 'YOUR_ADMIN_EMAIL@example.com');

drop policy if exists "admin update" on public.reviews;
create policy "admin update" on public.reviews
  for update to authenticated
  using ((auth.jwt() ->> 'email') = 'YOUR_ADMIN_EMAIL@example.com')
  with check ((auth.jwt() ->> 'email') = 'YOUR_ADMIN_EMAIL@example.com');

drop policy if exists "admin delete" on public.reviews;
create policy "admin delete" on public.reviews
  for delete to authenticated
  using ((auth.jwt() ->> 'email') = 'YOUR_ADMIN_EMAIL@example.com');

drop view if exists public.public_reviews;
create view public.public_reviews
  with (security_invoker = false) as
  select
    id,
    first_name,
    left(last_name, 1) as last_name,
    body,
    created_at
  from public.reviews
  where approved = true;

revoke all on public.public_reviews from public;
grant select on public.public_reviews to anon, authenticated;

create or replace function public.force_approved_false_on_insert()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if (auth.jwt() ->> 'email') is distinct from 'YOUR_ADMIN_EMAIL@example.com' then
    new.approved := false;
  end if;
  return new;
end;
$$;

drop trigger if exists trg_force_approved_false on public.reviews;
create trigger trg_force_approved_false
  before insert on public.reviews
  for each row
  execute function public.force_approved_false_on_insert();

create table if not exists public.review_audit (
  id          bigserial primary key,
  review_id   uuid,
  action      text not null,
  actor_email text,
  at          timestamptz not null default now()
);

alter table public.review_audit enable row level security;
revoke all on public.review_audit from anon, authenticated;
grant select on public.review_audit to authenticated;

drop policy if exists "admin view audit" on public.review_audit;
create policy "admin view audit" on public.review_audit
  for select to authenticated
  using ((auth.jwt() ->> 'email') = 'YOUR_ADMIN_EMAIL@example.com');

create or replace function public.log_review_change()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.review_audit (review_id, action, actor_email)
  values (
    coalesce(new.id, old.id),
    tg_op,
    coalesce(auth.jwt() ->> 'email', 'anon')
  );
  return coalesce(new, old);
end;
$$;

drop trigger if exists trg_log_review on public.reviews;
create trigger trg_log_review
  after insert or update or delete on public.reviews
  for each row
  execute function public.log_review_change();