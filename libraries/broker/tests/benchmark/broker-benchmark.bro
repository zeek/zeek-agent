
redef Broker::default_listen_retry=1secs;
redef exit_only_after_terminate = T;

type Stats: record {
    start: time;
    dt: interval;
    num_events: count &default=0;
};

global stats : Stats;

global stats_update: event(stats: Stats);

event event_1(i: int, s: string)
	{
	stats$num_events += 1;
	}

event event_2(ts: time, uid: string, id: conn_id, proto: transport_proto, service: string, duration: interval, orig_bytes: count, resp_bytes: count, conn_state: string, local_orig: bool, local_resp: bool, missed_bytes: count, history: string, orig_pkts: count, orig_ip_bytes: count, resp_pkts: count, resp_ip_bytes: count, tunnel_parents: set[string])
	{
	stats$num_events += 1;
	}

event event_3(ts: time, t: table[string] of set[string])
	{
	stats$num_events += 1;
	}

event quit_benchmark()
	{
	terminate();
	}

function clear_stats()
	{
	local s: Stats;
	stats = s;
	stats$start = current_time();
	}

event send_stats()
	{
	stats$dt = (current_time() - stats$start);
	local e = Broker::make_event(stats_update, stats);
	Broker::publish("/benchmark/stats", e);
	clear_stats();
	schedule 1secs { send_stats() };
	}

event zeek_init()
	{
	Broker::subscribe("/benchmark/events");
	Broker::subscribe("/benchmark/terminate");
	Broker::listen("127.0.0.1");
	clear_stats();
	schedule 1secs { send_stats() };
	}
