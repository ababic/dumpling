CREATE TABLE public.events (id int, happened_at timestamp with time zone, local_time time, the_date date);
INSERT INTO public.events (id, happened_at, local_time, the_date) VALUES (1, '2024-11-15 13:45:10+00', '13:46:51.500', '2024-11-17'), (2, '2024-11-16 00:03:14', '23:59:45', '2024-11-17');

COPY public.events (id, happened_at, local_time, the_date) FROM stdin;
3	2024-11-17 12:00:00+02	12:02:05	2024-11-20
\.
