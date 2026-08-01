-- ============================================================
-- Копилка приключений — настройка базы данных Supabase
-- ============================================================
-- Как использовать:
--   1. Зайдите в свой проект на https://supabase.com
--   2. Слева откройте "SQL Editor" -> "New query"
--   3. Вставьте целиком этот файл и нажмите "Run"
--   4. Готово — можно один раз выполнить, повторный запуск безопасен
--      (используются "create or replace" / "if not exists")
-- ============================================================

-- нужно для безопасного хранения PIN-кода (bcrypt-хэш, не открытым текстом)
create extension if not exists pgcrypto;

-- одна строка = один ребёнок/профиль
create table if not exists players (
  username   text primary key,
  pin_hash   text not null,
  state      jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- Row Level Security включена, но НИКАКИХ политик для anon-ключа не выдаётся —
-- то есть напрямую читать/писать таблицу через анонимный ключ нельзя.
-- Единственный доступ — через две функции ниже, которые сами проверяют PIN
-- внутри базы данных (security definer), прежде чем что-то отдать или сохранить.
alter table players enable row level security;

-- Вход или создание нового профиля.
-- Если имени ещё нет — создаёт профиль с этим PIN и пустым состоянием.
-- Если имя есть — сверяет PIN и возвращает сохранённые данные, либо ошибку.
create or replace function login_or_create(p_username text, p_pin text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  rec players%rowtype;
begin
  if p_username is null or length(trim(p_username)) = 0 then
    return jsonb_build_object('ok', false, 'error', 'bad_username');
  end if;
  if p_pin !~ '^[0-9]{6}$' then
    return jsonb_build_object('ok', false, 'error', 'bad_pin');
  end if;

  select * into rec from players where lower(username) = lower(trim(p_username));

  if not found then
    insert into players(username, pin_hash, state)
    values (trim(p_username), crypt(p_pin, gen_salt('bf')), '{}'::jsonb)
    returning * into rec;
    return jsonb_build_object('ok', true, 'created', true, 'state', rec.state);
  end if;

  if crypt(p_pin, rec.pin_hash) = rec.pin_hash then
    return jsonb_build_object('ok', true, 'created', false, 'state', rec.state);
  else
    return jsonb_build_object('ok', false, 'error', 'wrong_pin');
  end if;
end;
$$;

-- Сохранение прогресса. Тоже сверяет PIN внутри базы, прежде чем что-то менять.
create or replace function save_player_state(p_username text, p_pin text, p_state jsonb)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  rec players%rowtype;
begin
  select * into rec from players where lower(username) = lower(trim(p_username));
  if not found or crypt(p_pin, rec.pin_hash) <> rec.pin_hash then
    return jsonb_build_object('ok', false, 'error', 'auth_failed');
  end if;
  update players set state = p_state, updated_at = now()
  where lower(username) = lower(trim(p_username));
  return jsonb_build_object('ok', true);
end;
$$;

-- разрешаем анонимному ключу (тому, что вставляется в HTML-файл) вызывать
-- ТОЛЬКО эти две функции — не саму таблицу
grant execute on function login_or_create(text, text) to anon;
grant execute on function save_player_state(text, text, jsonb) to anon;
