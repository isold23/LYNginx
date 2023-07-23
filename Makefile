
default:	build

clean:
	rm -rf Makefile objs

build:
	$(MAKE) -f objs/Makefile

install:
	$(MAKE) -f objs/Makefile install

modules:
	$(MAKE) -f objs/Makefile modules

upgrade:
	/opt/app/nginx-reverse-proxy/sbin/nginx -t

	kill -USR2 `cat /opt/app/nginx-reverse-proxy/logs/nginx.pid`
	sleep 1
	test -f /opt/app/nginx-reverse-proxy/logs/nginx.pid.oldbin

	kill -QUIT `cat /opt/app/nginx-reverse-proxy/logs/nginx.pid.oldbin`
