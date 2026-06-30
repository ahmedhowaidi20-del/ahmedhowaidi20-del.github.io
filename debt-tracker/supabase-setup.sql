-- Run this entire file in your Supabase SQL Editor (once)
-- Dashboard → SQL Editor → New query → paste → Run

create table if not exists people (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  created_at timestamptz default now()
);

create table if not exists transactions (
  id uuid primary key default gen_random_uuid(),
  person_id uuid references people(id) on delete cascade,
  amount numeric not null,          -- positive = they owe me, negative = I owe them
  description text not null,
  type_label text not null,
  created_at timestamptz default now()
);

-- Allow public read/write (no auth needed for personal use)
alter table people enable row level security;
alter table transactions enable row level security;

create policy "allow all on people" on people for all using (true) with check (true);
create policy "allow all on transactions" on transactions for all using (true) with check (true);
