/* ==============================================================================
   FILE 1: supabase_schema.sql
   Aplikasi : POS Penjualan Sosis Naga
   Arsitektur: DASarsitek Vercel + Supabase (Instant UX Edition)
   Role      : admin, kasir
   Access    : Private Portal (Wajib Login)
   ============================================================================== */

/* A. FUNGSI UMUM */
create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

/* B. TABEL PROFILES (SINKRON DENGAN AUTH.USERS) */
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  nama text not null default '',
  role text not null default 'admin' check (role in ('admin', 'kasir')),
  aktif boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

drop trigger if exists set_updated_at_profiles on public.profiles;
create trigger set_updated_at_profiles
  before update on public.profiles
  for each row execute function public.set_updated_at();

alter table public.profiles enable row level security;

/* C. FUNGSI HELPER RLS (SECURITY DEFINER) */
create or replace function public.current_app_role()
returns text
language sql
stable
security definer
set search_path = ''
as $$
  select p.role from public.profiles p where p.id = (select auth.uid()) and p.aktif = true;
$$;

create or replace function public.is_active()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (select 1 from public.profiles p where p.id = (select auth.uid()) and p.aktif = true);
$$;

create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce(public.current_app_role() = 'admin', false);
$$;

create or replace function public.has_role(roles text[])
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce(public.current_app_role() = 'admin' or public.current_app_role() = any (roles), false);
$$;

grant execute on function public.current_app_role(), public.is_active(), public.is_admin(), public.has_role(text[]) to authenticated;

/* D. TRIGGER USER BARU -> PROFILES (AUTO ADMIN JIKA DARI DASHBOARD) */
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_role text;
begin
  /* app_metadata hanya bisa ditulis oleh server admin gateway via service key */
  v_role := coalesce(nullif(new.raw_app_meta_data ->> 'role', ''), 'admin');
  if v_role not in ('admin', 'kasir') then
    v_role := 'admin';
  end if;

  insert into public.profiles (id, email, nama, role, aktif)
  values (
    new.id,
    new.email,
    coalesce(nullif(new.raw_user_meta_data ->> 'nama', ''), split_part(new.email, '@', 1)),
    v_role,
    true
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

revoke execute on function public.handle_new_user() from public, anon, authenticated;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

/* Backfill user yang sudah ada */
insert into public.profiles (id, email, nama, role, aktif)
select u.id, u.email, coalesce(split_part(u.email, '@', 1), 'Admin'), 'admin', true
from auth.users u
on conflict (id) do nothing;

/* E. POLICIES PROFILES */
grant select, update on public.profiles to authenticated;

drop policy if exists "profiles_select" on public.profiles;
create policy "profiles_select" on public.profiles
  for select to authenticated
  using (id = (select auth.uid()) or public.is_admin());

drop policy if exists "profiles_update_self" on public.profiles;
create policy "profiles_update_self" on public.profiles
  for update to authenticated
  using (id = (select auth.uid()))
  with check (id = (select auth.uid()));

revoke update on public.profiles from authenticated;
grant update (nama) on public.profiles to authenticated;

/* F. COUNTER NOMOR URUT ATOMIK */
create table if not exists public.counters (
  nama text primary key,
  nilai bigint not null default 0
);
alter table public.counters enable row level security;

create or replace function public.next_code(p_nama text, p_prefix text)
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  v bigint;
begin
  if not public.is_active() then
    raise exception 'Akses ditolak: User tidak aktif atau belum terdaftar';
  end if;

  insert into public.counters (nama, nilai)
  values (p_nama, 1)
  on conflict (nama) do update
  set nilai = public.counters.nilai + 1
  returning nilai into v;

  return p_prefix || '-' || to_char(now() at time zone 'Asia/Jakarta', 'YYYYMMDD') || '-' || lpad(v::text, 4, '0');
end;
$$;
grant execute on function public.next_code(text, text) to authenticated;

/* G. LOG AUDIT AKTIVITAS */
create table if not exists public.logs (
  id uuid primary key default gen_random_uuid(),
  aksi text not null,
  target text,
  detail jsonb,
  created_at timestamptz not null default now(),
  created_by uuid default auth.uid() references auth.users(id) on delete set null
);
alter table public.logs enable row level security;
grant select, insert on public.logs to authenticated;

drop policy if exists "logs_select" on public.logs;
create policy "logs_select" on public.logs
  for select to authenticated
  using (public.is_admin());

drop policy if exists "logs_insert" on public.logs;
create policy "logs_insert" on public.logs
  for insert to authenticated
  with check (public.is_active() and created_by = (select auth.uid()));

/* H. TABEL MASTER PRODUK */
create table if not exists public.produk (
  id uuid primary key default gen_random_uuid(),
  kode text unique,
  nama text not null check (char_length(nama) between 1 and 120),
  kategori text not null default 'Sosis Bakar',
  harga_modal bigint not null default 0 check (harga_modal >= 0),
  harga_jual bigint not null default 0 check (harga_jual >= 0),
  stok integer not null default 0 check (stok >= 0),
  minimum_stok integer not null default 5 check (minimum_stok >= 0),
  gambar_url text,
  aktif boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  created_by uuid default auth.uid() references auth.users(id) on delete set null
);

create index if not exists produk_kode_idx on public.produk (kode);
create index if not exists produk_kategori_idx on public.produk (kategori);
create index if not exists produk_aktif_idx on public.produk (aktif);

drop trigger if exists set_updated_at_produk on public.produk;
create trigger set_updated_at_produk
  before update on public.produk
  for each row execute function public.set_updated_at();

alter table public.produk enable row level security;
grant select, insert, update, delete on public.produk to authenticated;

drop policy if exists "produk_select" on public.produk;
create policy "produk_select" on public.produk
  for select to authenticated
  using (public.is_active());

drop policy if exists "produk_insert" on public.produk;
create policy "produk_insert" on public.produk
  for insert to authenticated
  with check (public.is_admin() and created_by = (select auth.uid()));

drop policy if exists "produk_update" on public.produk;
create policy "produk_update" on public.produk
  for update to authenticated
  using (public.is_admin() or public.has_role(array['kasir']))
  with check (public.is_admin() or public.has_role(array['kasir']));

drop policy if exists "produk_delete" on public.produk;
create policy "produk_delete" on public.produk
  for delete to authenticated
  using (public.is_admin());

/* I. TABEL TRANSAKSI PENJUALAN */
create table if not exists public.transaksi (
  id uuid primary key default gen_random_uuid(),
  kode text unique not null,
  tanggal timestamptz not null default now(),
  user_id uuid references public.profiles(id) on delete restrict,
  kasir_nama text not null default 'Kasir',
  total bigint not null default 0 check (total >= 0),
  bayar bigint not null default 0 check (bayar >= 0),
  kembalian bigint not null default 0 check (kembalian >= 0),
  metode_pembayaran text not null default 'Tunai',
  catatan text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  created_by uuid default auth.uid() references auth.users(id) on delete set null
);

create index if not exists transaksi_kode_idx on public.transaksi (kode);
create index if not exists transaksi_tanggal_idx on public.transaksi (tanggal desc);
create index if not exists transaksi_user_id_idx on public.transaksi (user_id);

drop trigger if exists set_updated_at_transaksi on public.transaksi;
create trigger set_updated_at_transaksi
  before update on public.transaksi
  for each row execute function public.set_updated_at();

alter table public.transaksi enable row level security;
grant select, insert on public.transaksi to authenticated;

drop policy if exists "transaksi_select" on public.transaksi;
create policy "transaksi_select" on public.transaksi
  for select to authenticated
  using (public.is_admin() or user_id = (select auth.uid()));

drop policy if exists "transaksi_insert" on public.transaksi;
create policy "transaksi_insert" on public.transaksi
  for insert to authenticated
  with check (public.has_role(array['kasir']) and created_by = (select auth.uid()));

/* J. TABEL DETAIL TRANSAKSI */
create table if not exists public.detail_transaksi (
  id uuid primary key default gen_random_uuid(),
  transaksi_id uuid not null references public.transaksi(id) on delete cascade,
  produk_id uuid not null references public.produk(id) on delete restrict,
  produk_nama text not null,
  harga_modal bigint not null default 0 check (harga_modal >= 0),
  harga bigint not null default 0 check (harga >= 0),
  qty integer not null check (qty > 0),
  subtotal bigint not null default 0 check (subtotal >= 0),
  created_at timestamptz not null default now()
);

create index if not exists detail_transaksi_trx_idx on public.detail_transaksi (transaksi_id);
create index if not exists detail_transaksi_prd_idx on public.detail_transaksi (produk_id);

alter table public.detail_transaksi enable row level security;
grant select, insert on public.detail_transaksi to authenticated;

drop policy if exists "detail_transaksi_select" on public.detail_transaksi;
create policy "detail_transaksi_select" on public.detail_transaksi
  for select to authenticated
  using (
    public.is_admin() or exists (
      select 1 from public.transaksi t
      where t.id = detail_transaksi.transaksi_id
      and t.user_id = (select auth.uid())
    )
  );

drop policy if exists "detail_transaksi_insert" on public.detail_transaksi;
create policy "detail_transaksi_insert" on public.detail_transaksi
  for insert to authenticated
  with check (public.has_role(array['kasir']));

/* K. TABEL RIWAYAT MUTASI STOK */
create table if not exists public.stok_mutasi (
  id uuid primary key default gen_random_uuid(),
  produk_id uuid not null references public.produk(id) on delete restrict,
  tanggal timestamptz not null default now(),
  jenis text not null check (jenis in ('masuk', 'penyesuaian', 'penjualan')),
  qty integer not null,
  keterangan text,
  created_at timestamptz not null default now(),
  created_by uuid default auth.uid() references auth.users(id) on delete set null
);

create index if not exists stok_mutasi_prd_idx on public.stok_mutasi (produk_id);
create index if not exists stok_mutasi_tgl_idx on public.stok_mutasi (tanggal desc);

alter table public.stok_mutasi enable row level security;
grant select, insert on public.stok_mutasi to authenticated;

drop policy if exists "stok_mutasi_select" on public.stok_mutasi;
create policy "stok_mutasi_select" on public.stok_mutasi
  for select to authenticated
  using (public.is_active());

drop policy if exists "stok_mutasi_insert" on public.stok_mutasi;
create policy "stok_mutasi_insert" on public.stok_mutasi
  for insert to authenticated
  with check (public.is_active());

/* L. TABEL BIAYA OPERASIONAL */
create table if not exists public.biaya (
  id uuid primary key default gen_random_uuid(),
  tanggal date not null default current_date,
  kategori text not null,
  keterangan text not null,
  jumlah bigint not null check (jumlah > 0),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  created_by uuid default auth.uid() references auth.users(id) on delete set null
);

create index if not exists biaya_tanggal_idx on public.biaya (tanggal desc);

drop trigger if exists set_updated_at_biaya on public.biaya;
create trigger set_updated_at_biaya
  before update on public.biaya
  for each row execute function public.set_updated_at();

alter table public.biaya enable row level security;
grant select, insert, update, delete on public.biaya to authenticated;

drop policy if exists "biaya_select" on public.biaya;
create policy "biaya_select" on public.biaya
  for select to authenticated
  using (public.is_admin());

drop policy if exists "biaya_insert" on public.biaya;
create policy "biaya_insert" on public.biaya
  for insert to authenticated
  with check (public.is_admin() and created_by = (select auth.uid()));

drop policy if exists "biaya_update" on public.biaya;
create policy "biaya_update" on public.biaya
  for update to authenticated
  using (public.is_admin())
  with check (public.is_admin());

drop policy if exists "biaya_delete" on public.biaya;
create policy "biaya_delete" on public.biaya
  for delete to authenticated
  using (public.is_admin());

/* M. TABEL PAJAK */
create table if not exists public.pajak (
  id uuid primary key default gen_random_uuid(),
  periode text not null,
  jenis_pajak text not null,
  tarif numeric(6, 2) not null check (tarif >= 0),
  dasar_pengenaan bigint not null default 0 check (dasar_pengenaan >= 0),
  nilai_pajak bigint not null default 0 check (nilai_pajak >= 0),
  keterangan text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  created_by uuid default auth.uid() references auth.users(id) on delete set null
);

create index if not exists pajak_periode_idx on public.pajak (periode);

drop trigger if exists set_updated_at_pajak on public.pajak;
create trigger set_updated_at_pajak
  before update on public.pajak
  for each row execute function public.set_updated_at();

alter table public.pajak enable row level security;
grant select, insert, update, delete on public.pajak to authenticated;

drop policy if exists "pajak_select" on public.pajak;
create policy "pajak_select" on public.pajak
  for select to authenticated
  using (public.is_admin());

drop policy if exists "pajak_insert" on public.pajak;
create policy "pajak_insert" on public.pajak
  for insert to authenticated
  with check (public.is_admin() and created_by = (select auth.uid()));

drop policy if exists "pajak_update" on public.pajak;
create policy "pajak_update" on public.pajak
  for update to authenticated
  using (public.is_admin())
  with check (public.is_admin());

drop policy if exists "pajak_delete" on public.pajak;
create policy "pajak_delete" on public.pajak
  for delete to authenticated
  using (public.is_admin());

/* N. TABEL DAFTAR AKUN (CHART OF ACCOUNTS) */
create table if not exists public.akun (
  id uuid primary key default gen_random_uuid(),
  kode_akun text unique not null,
  nama_akun text not null,
  jenis_akun text not null check (jenis_akun in ('Aset', 'Kewajiban', 'Ekuitas', 'Pendapatan', 'Beban')),
  status boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  created_by uuid default auth.uid() references auth.users(id) on delete set null
);

create index if not exists akun_kode_idx on public.akun (kode_akun);

drop trigger if exists set_updated_at_akun on public.akun;
create trigger set_updated_at_akun
  before update on public.akun
  for each row execute function public.set_updated_at();

alter table public.akun enable row level security;
grant select, insert, update, delete on public.akun to authenticated;

drop policy if exists "akun_select" on public.akun;
create policy "akun_select" on public.akun
  for select to authenticated
  using (public.is_admin());

drop policy if exists "akun_insert" on public.akun;
create policy "akun_insert" on public.akun
  for insert to authenticated
  with check (public.is_admin() and created_by = (select auth.uid()));

drop policy if exists "akun_update" on public.akun;
create policy "akun_update" on public.akun
  for update to authenticated
  using (public.is_admin())
  with check (public.is_admin());

drop policy if exists "akun_delete" on public.akun;
create policy "akun_delete" on public.akun
  for delete to authenticated
  using (public.is_admin());

/* O. TABEL BUKU BESAR / JURNAL UMUM */
create table if not exists public.buku_besar (
  id uuid primary key default gen_random_uuid(),
  nomor_jurnal text not null,
  tanggal date not null default current_date,
  referensi text,
  akun_id uuid not null references public.akun(id) on delete restrict,
  keterangan text not null,
  debit bigint not null default 0 check (debit >= 0),
  kredit bigint not null default 0 check (kredit >= 0),
  created_at timestamptz not null default now(),
  created_by uuid default auth.uid() references auth.users(id) on delete set null
);

create index if not exists buku_besar_jurnal_idx on public.buku_besar (nomor_jurnal);
create index if not exists buku_besar_tanggal_idx on public.buku_besar (tanggal desc);
create index if not exists buku_besar_akun_idx on public.buku_besar (akun_id);

alter table public.buku_besar enable row level security;
grant select, insert on public.buku_besar to authenticated;

drop policy if exists "buku_besar_select" on public.buku_besar;
create policy "buku_besar_select" on public.buku_besar
  for select to authenticated
  using (public.is_admin());

drop policy if exists "buku_besar_insert" on public.buku_besar;
create policy "buku_besar_insert" on public.buku_besar
  for insert to authenticated
  with check (public.is_admin() and created_by = (select auth.uid()));

/* P. OPERASI ATOMIK MULTI-TABEL: SIMPAN TRANSAKSI */
create or replace function public.simpan_transaksi(p_payload jsonb)
returns jsonb
language plpgsql
security invoker
as $$
declare
  v_user_id uuid;
  v_kasir_nama text;
  v_total bigint;
  v_bayar bigint;
  v_kembalian bigint;
  v_catatan text;
  v_trx_id uuid;
  v_trx_kode text;
  v_item record;
  v_stok_cur integer;
  v_items_arr jsonb;
  v_akun_kas_id uuid;
  v_akun_penjualan_id uuid;
  v_akun_hpp_id uuid;
  v_akun_persediaan_id uuid;
  v_total_hpp bigint := 0;
begin
  /* Validasi sesi dan peran */
  if not public.has_role(array['kasir', 'admin']) then
    raise exception 'Akses ditolak: Hanya kasir atau admin yang dapat membuat transaksi';
  end if;

  v_user_id := (select auth.uid());
  select coalesce(nama, 'Kasir') into v_kasir_nama from public.profiles where id = v_user_id;

  v_total := coalesce((p_payload ->> 'total')::bigint, 0);
  v_bayar := coalesce((p_payload ->> 'bayar')::bigint, 0);
  v_kembalian := coalesce((p_payload ->> 'kembalian')::bigint, 0);
  v_catatan := p_payload ->> 'catatan';
  v_items_arr := p_payload -> 'items';

  if v_items_arr is null or jsonb_array_length(v_items_arr) = 0 then
    raise exception 'Transaksi gagal: Keranjang belanja kosong';
  end if;

  if v_bayar < v_total then
    raise exception 'Transaksi gagal: Jumlah pembayaran kurang dari total transaksi';
  end if;

  /* Cek ketersediaan stok setiap produk */
  for v_item in select * from jsonb_to_recordset(v_items_arr) as x(
    produk_id uuid,
    qty integer,
    harga bigint,
    harga_modal bigint,
    produk_nama text
  )
  loop
    select stok into v_stok_cur from public.produk where id = v_item.produk_id and aktif = true for update;
    if not found then
      raise exception 'Produk ID % tidak ditemukan atau nonaktif', v_item.produk_id;
    end if;
    if v_stok_cur < v_item.qty then
      raise exception 'Stok tidak mencukupi untuk % (Sisa: %, Diminta: %)', v_item.produk_nama, v_stok_cur, v_item.qty;
    end if;
  end loop;

  /* Generate kode transaksi */
  v_trx_kode := public.next_code('transaksi', 'TRX');
  v_trx_id := gen_random_uuid();

  /* Insert transaksi utama */
  insert into public.transaksi (id, kode, tanggal, user_id, kasir_nama, total, bayar, kembalian, catatan, created_by)
  values (v_trx_id, v_trx_kode, now(), v_user_id, v_kasir_nama, v_total, v_bayar, v_kembalian, v_catatan, v_user_id);

  /* Insert detail transaksi, potong stok, catat mutasi */
  for v_item in select * from jsonb_to_recordset(v_items_arr) as x(
    produk_id uuid,
    qty integer,
    harga bigint,
    harga_modal bigint,
    produk_nama text
  )
  loop
    insert into public.detail_transaksi (transaksi_id, produk_id, produk_nama, harga_modal, harga, qty, subtotal)
    values (v_trx_id, v_item.produk_id, v_item.produk_nama, v_item.harga_modal, v_item.harga, v_item.qty, (v_item.harga * v_item.qty));

    update public.produk
    set stok = stok - v_item.qty
    where id = v_item.produk_id and stok >= v_item.qty;

    insert into public.stok_mutasi (produk_id, tanggal, jenis, qty, keterangan, created_by)
    values (v_item.produk_id, now(), 'penjualan', -v_item.qty, 'Penjualan Nota ' || v_trx_kode, v_user_id);

    v_total_hpp := v_total_hpp + (v_item.harga_modal * v_item.qty);
  end loop;

  /* Pencatatan Buku Besar Otomatis jika akun telah disiapkan */
  select id into v_akun_kas_id from public.akun where kode_akun = '1001' limit 1;
  select id into v_akun_penjualan_id from public.akun where kode_akun = '4001' limit 1;
  select id into v_akun_hpp_id from public.akun where kode_akun = '5001' limit 1;
  select id into v_akun_persediaan_id from public.akun where kode_akun = '1101' limit 1;

  if v_akun_kas_id is not null and v_akun_penjualan_id is not null then
    /* Jurnal Penjualan: Kas (Debit) vs Pendapatan Penjualan (Kredit) */
    insert into public.buku_besar (nomor_jurnal, tanggal, referensi, akun_id, keterangan, debit, kredit, created_by)
    values (v_trx_kode, current_date, v_trx_kode, v_akun_kas_id, 'Penerimaan Penjualan Sosis Naga ' || v_trx_kode, v_total, 0, v_user_id);

    insert into public.buku_besar (nomor_jurnal, tanggal, referensi, akun_id, keterangan, debit, kredit, created_by)
    values (v_trx_kode, current_date, v_trx_kode, v_akun_penjualan_id, 'Pendapatan Penjualan Sosis Naga ' || v_trx_kode, 0, v_total, v_user_id);

    /* Jurnal HPP: Beban HPP (Debit) vs Persediaan (Kredit) */
    if v_akun_hpp_id is not null and v_akun_persediaan_id is not null and v_total_hpp > 0 then
      insert into public.buku_besar (nomor_jurnal, tanggal, referensi, akun_id, keterangan, debit, kredit, created_by)
      values (v_trx_kode, current_date, v_trx_kode, v_akun_hpp_id, 'HPP Penjualan ' || v_trx_kode, v_total_hpp, 0, v_user_id);

      insert into public.buku_besar (nomor_jurnal, tanggal, referensi, akun_id, keterangan, debit, kredit, created_by)
      values (v_trx_kode, current_date, v_trx_kode, v_akun_persediaan_id, 'Pengurangan Persediaan ' || v_trx_kode, 0, v_total_hpp, v_user_id);
    end if;
  end if;

  /* Catat log audit */
  insert into public.logs (aksi, target, detail, created_by)
  values ('TRANSAKSI_SELESAI', v_trx_kode, jsonb_build_object('total', v_total, 'item_count', jsonb_array_length(v_items_arr)), v_user_id);

  return jsonb_build_object(
    'success', true,
    'transaksi_id', v_trx_id,
    'kode', v_trx_kode,
    'total', v_total,
    'bayar', v_bayar,
    'kembalian', v_kembalian
  );
end;
$$;
grant execute on function public.simpan_transaksi(jsonb) to authenticated;

/* Q. OPERASI ATOMIK PENYESUAIAN STOK */
create or replace function public.sesuaikan_stok(
  p_produk_id uuid,
  p_jenis text,
  p_qty integer,
  p_keterangan text
)
returns jsonb
language plpgsql
security invoker
as $$
declare
  v_user_id uuid;
  v_stok_lama integer;
  v_stok_baru integer;
begin
  if not public.is_admin() then
    raise exception 'Akses ditolak: Hanya admin yang dapat menyesuaikan stok manual';
  end if;

  v_user_id := (select auth.uid());

  select stok into v_stok_lama from public.produk where id = p_produk_id for update;
  if not found then
    raise exception 'Produk tidak ditemukan';
  end if;

  if p_jenis = 'masuk' then
    v_stok_baru := v_stok_lama + p_qty;
  elsif p_jenis = 'penyesuaian' then
    v_stok_baru := p_qty;
  else
    raise exception 'Jenis penyesuaian tidak valid';
  end if;

  if v_stok_baru < 0 then
    raise exception 'Stok tidak boleh negatif';
  end if;

  update public.produk
  set stok = v_stok_baru
  where id = p_produk_id;

  insert into public.stok_mutasi (produk_id, tanggal, jenis, qty, keterangan, created_by)
  values (p_produk_id, now(), p_jenis, (v_stok_baru - v_stok_lama), p_keterangan, v_user_id);

  return jsonb_build_object(
    'success', true,
    'produk_id', p_produk_id,
    'stok_lama', v_stok_lama,
    'stok_baru', v_stok_baru
  );
end;
$$;
grant execute on function public.sesuaikan_stok(uuid, text, integer, text) to authenticated;

/* R. DATA AWAL (AUTO-SEED, IDEMPOTENT) */
/* Seed Akun Default */
insert into public.akun (kode_akun, nama_akun, jenis_akun, status)
values
  ('1001', 'Kas Kasir & Operasional', 'Aset', true),
  ('1002', 'Bank Rekening Operasional', 'Aset', true),
  ('1101', 'Persediaan Produk Sosis Naga', 'Aset', true),
  ('2001', 'Utang Usaha & Supplier', 'Kewajiban', true),
  ('3001', 'Modal Pemilik', 'Ekuitas', true),
  ('4001', 'Pendapatan Penjualan Sosis Naga', 'Pendapatan', true),
  ('5001', 'Beban Pokok Penjualan (HPP)', 'Beban', true),
  ('6001', 'Beban Listrik, Gas & Operasional', 'Beban', true),
  ('6002', 'Beban Gaji Kasir & Karyawan', 'Beban', true),
  ('6003', 'Beban Pajak Usaha & Retribusi', 'Beban', true)
on conflict (kode_akun) do nothing;

/* Seed Produk Awal Sosis Naga */
insert into public.produk (kode, nama, kategori, harga_modal, harga_jual, stok, minimum_stok, aktif)
values
  ('SN-001', 'Sosis Naga Jumbo Bakar Saus BBQ', 'Sosis Bakar', 8000, 15000, 50, 10, true),
  ('SN-002', 'Sosis Naga Super Pedas Level 5', 'Sosis Bakar', 8500, 16000, 45, 10, true),
  ('SN-003', 'Sosis Naga Keju Lumer Melted', 'Spesial Keju', 10000, 18000, 40, 10, true),
  ('SN-004', 'Sosis Naga Blackpepper Lada Hitam', 'Sosis Bakar', 8500, 16000, 35, 10, true),
  ('SN-005', 'Paket Hemat Duo Naga + Es Teh Manis', 'Paket Hemat', 14000, 25000, 30, 8, true),
  ('SN-006', 'Sosis Naga Mini Crispy (Isi 3)', 'Snack', 7000, 13000, 4, 10, true), /* trigger stok menipis */
  ('SN-007', 'Es Teh Lemon Sosis Naga', 'Minuman', 2000, 5000, 80, 15, true)
on conflict (kode) do nothing;

/* Seed Contoh Biaya Operasional Awal */
insert into public.biaya (tanggal, kategori, keterangan, jumlah)
select current_date, 'Bahan Baku & Gas', 'Pembelian Gas Elpiji 3kg & Saus BBQ Tambahan', 120000
where not exists (select 1 from public.biaya limit 1);

/* S. REALTIME PUBLICATION */
do $$
begin
  alter publication supabase_realtime add table public.produk;
  alter publication supabase_realtime add table public.transaksi;
  alter publication supabase_realtime add table public.stok_mutasi;
exception
  when duplicate_object then null;
end $$;

/* T. NOTIFY SCHEMA RELOAD */
notify pgrst, 'reload schema';
