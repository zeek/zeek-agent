# ping.zeek

redef exit_only_after_terminate = T;

global pong: event(n: int);

event ping(n: int)
	{
	event pong(n);
	}

event zeek_init()
	{
	Broker::subscribe("/topic/test");
	Broker::listen("127.0.0.1", 9999/tcp);
	Broker::auto_publish("/topic/test", pong);
	}
