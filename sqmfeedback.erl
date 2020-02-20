-module(sqmfeedback).
-export([main/0,monitor_ifaces/2,monitor_a_site/1,adjuster/1,monitor_delays/2,timer_process/2 ]).



pingtimes_ms(I,N,S) -> 
    Pingstr = os:cmd(io_lib:format("ping -c ~B -i 0.2 -s ~B ~s",[N,S,I])),
    
    [_|Lines]=string:split(Pingstr,"\n",all),
    TT = lists:sublist(lists:flatten([re:replace(L,".*time=([0-9.]+) ms","\\1") || L <- Lines]),N),
    Times = lists:sort([binary_to_float(T) || T <-TT]),
    io:format("ping ~s with results: ~w\n",[I,Times]),
    Times.



new_bandwidth(Cmd,NewBW) ->
    %os:cmd(io_lib:format(Cmd,[NewBW])).
    io:format(Cmd,[NewBW]).

monitor_a_site(Rpid,Name,N,Inc,FiveTimes) ->
    T = rand:uniform()*20+10, % sleep 10 to 30 seconds
    timer:sleep(round(T*1000)),
    MS = pingtimes_ms(Name,N,50),
    Times = lists:sort(lists:append(FiveTimes,MS)),
    Delay= lists:last(Times) - lists:nth(5,Times),
    if Delay > 20.0 -> 
	    Rpid ! {delay,Name,Delay,erlang:system_time(seconds)};
       true -> 
	    true
    end,
    monitor_a_site(Rpid,Name,N,Inc,lists:sublist(Times,2,5)). % throw out the lowest, keep the next 5


monitor_a_site(Monitor) ->
    {RPid,Name} = Monitor,
    T = pingtimes_ms(Name,5,50),
    monitor_a_site(RPid,Name,5,20,T).
    

monitor_delays(RepPid, Sites) ->
    receive 
	{delay,Site,Delay,Time} ->
	    NewSites=[{Site,Delay,Time}|Sites],
	    monitor_delays(RepPid,NewSites);
	{timer,Time} -> 
	    io:format("Checking up on things: ~B\n",[erlang:system_time(seconds)]),
	    Now=erlang:system_time(seconds),
	    RecentSites = [{Site, Del, T} || {Site,Del,T} <- Sites, T > Now-30],
	    if length(RecentSites) > 3 ->
		    Factor = rand:uniform() * 0.15 + 0.85,
		    RepPid ! {factor,Factor};
	       true ->
		    Factor = rand:uniform() * 0.15 + 1.0,
		    RepPid ! {factor,Factor}
	    end,
	    monitor_delays(RepPid,RecentSites)
    end.



adjuster(Tuples) ->
    receive
	{factor,F} ->
	    [{I1,L1,C1,H1},{I2,L2,C2,H2}] = Tuples,
	    CC1 = min(max(L1,C1*F),H1),
	    CC2 = min(max(L2,C2*F),H2),
	    new_bandwidth(I1,CC1),
	    new_bandwidth(I2,CC2),
	    adjuster([{I1,L1,CC1,H1},{I2,L2,CC2,H2}])
    end.


timer_process(P,T) ->
    timer:send_interval(30000,P,{timer,erlang:system_time(seconds)}).



monitor_ifaces(Tuples,Sites) ->
    SitePids = lists:map(fun(Tup) -> spawn(sqmfeedback,monitor_a_site,[Tup]) end,[{self(),S}||S <- Sites]),
    AdjPid = spawn(sqmfeedback,adjuster,[Tuples]),
    MonPid = spawn(sqmfeedback,monitor_delays,[AdjPid,[]]),
    TimerPid = spawn(sqmfeedback,timer_process,[MonPid,40]).


main() ->
    
    monitor_ifaces([{"tc qdisc change root dev eth0.2 cake bandwidth ~BKbit diffserv4 dual-srchost overhead 34 ", 4000, 6000, 8000},
		    {"tc qdisc change root dev ifb4eth0.2 cake bandwidth ~BKbit diffserv4 dual-dsthost nat overhead 34 ingress",15000,30000,35000}],
    ["dns.google.com","one.one.one.one","quad9.net","facebook.com",
     "gstatic.com","cloudflare.com","fbcdn.com","akamai.com","amazon.com"]),
    receive
	true -> true
    end.


