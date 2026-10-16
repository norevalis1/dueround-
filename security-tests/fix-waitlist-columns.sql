-- Fix: waitlist speed limit could be skipped by backdating created_at.
-- The page only ever sends these six columns, so the public key may only fill
-- those. id and created_at always come from the database.
-- Also removes table rights the public key never needs (TRUNCATE skips row
-- rules entirely; nothing in the apps uses TRIGGER or REFERENCES).
begin;
revoke insert on public.waitlist from anon, authenticated;
grant insert (email, trade, tracking, source, page, wants) on public.waitlist to anon, authenticated;
revoke truncate, trigger, references on public.habits, public.check_ins, public.push_subscriptions from anon, authenticated;
commit;
