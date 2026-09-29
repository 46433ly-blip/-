-- ============================================================
-- بک‌اند نظرات سایت علیرضا پاپی (Supabase)
-- اجرا: Supabase Dashboard > SQL Editor > New query > Paste > Run
-- قبل از اجرا: عبارت YOUR_ADMIN_EMAIL@example.com را با ایمیل خودت عوض کن
-- (همان ایمیلی که برای ورود مدیر می‌سازی)
-- ============================================================

create extension if not exists pgcrypto;

create table if not exists public.reviews (
  id          uuid primary key default gen_random_uuid(),
  first_name  text not null check (char_length(first_name) between 2 and 30),
  last_name   text not null check (char_length(last_name)  between 1 and 30),
  email       text not null check (char_length(email) <= 80 and email ~* '^[^@\s]+@[^@\s]+$'),
  body        text not null check (char_length(body) between 10 and 500),
  approved    boolean not null default false,
  created_at  timestamptz not null default now()
);

alter table public.reviews enable row level security;

-- هیچ دسترسی پیش‌فرضی برای بازدیدکننده‌ها
revoke all on public.reviews from anon, authenticated;

-- بازدیدکننده فقط می‌تواند این ۴ ستون را بفرستد (نمی‌تواند approved را true کند)
grant insert (first_name, last_name, email, body) on public.reviews to anon;
create policy "anyone can submit pending review"
  on public.reviews for insert to anon
  with check (approved = false);

-- مدیر (فقط ایمیل خودت): خواندن، افزودن، تأیید/ویرایش و حذف
grant select, insert, update, delete on public.reviews to authenticated;

create policy "admin select" on public.reviews for select to authenticated
  using ((auth.jwt() ->> 'email') = 'YOUR_ADMIN_EMAIL@example.com');
create policy "admin insert" on public.reviews for insert to authenticated
  with check ((auth.jwt() ->> 'email') = 'YOUR_ADMIN_EMAIL@example.com');
create policy "admin update" on public.reviews for update to authenticated
  using ((auth.jwt() ->> 'email') = 'YOUR_ADMIN_EMAIL@example.com')
  with check ((auth.jwt() ->> 'email') = 'YOUR_ADMIN_EMAIL@example.com');
create policy "admin delete" on public.reviews for delete to authenticated
  using ((auth.jwt() ->> 'email') = 'YOUR_ADMIN_EMAIL@example.com');

-- نمای عمومی: فقط نظرهای تأییدشده، بدون ایمیل، و فقط حرف اول نام خانوادگی
create or replace view public.public_reviews as
  select id, first_name, left(last_name, 1) as last_name, body, created_at
  from public.reviews
  where approved = true;

grant select on public.public_reviews to anon, authenticated;

-- ============================================================
-- افزودن: بلاک کردن ایمیل مزاحم/اسپم (اجرا بعد از بلوک بالا)
-- ============================================================
create table if not exists public.blocked_emails (
  email text primary key,
  blocked_at timestamptz not null default now()
);
alter table public.blocked_emails enable row level security;
revoke all on public.blocked_emails from anon, authenticated;
grant select, insert, delete on public.blocked_emails to authenticated;

create policy "admin manage blocklist" on public.blocked_emails for all to authenticated
  using ((auth.jwt() ->> 'email') = 'YOUR_ADMIN_EMAIL@example.com')
  with check ((auth.jwt() ->> 'email') = 'YOUR_ADMIN_EMAIL@example.com');

create or replace function public.is_blocked(p_email text)
returns boolean language sql stable security definer set search_path = public as $$
  select exists(select 1 from public.blocked_emails where email = lower(p_email));
$$;
grant execute on function public.is_blocked(text) to anon;

drop policy if exists "anyone can submit pending review" on public.reviews;
create policy "anyone can submit pending review"
  on public.reviews for insert to anon
  with check (approved = false and not public.is_blocked(email));
