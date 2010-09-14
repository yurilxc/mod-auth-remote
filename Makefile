APACHE_ROOT=/usr/local/apache2
MODULE_NAME=mod_auth_remote

all:$(MODULE_NAME).c $(MODULE_NAME).h
	$(APACHE_ROOT)/bin/apxs -c $(MODULE_NAME).c $(MODULE_NAME).h

#load the module into apache's /module directory
.PHONY:install
install:
	$(APACHE_ROOT)/bin/apxs -i $(MODULE_NAME).la

.PHONY:clean
clean:
	-rm $(MODULE_NAME).la $(MODULE_NAME).o $(MODULE_NAME).lo $(MODULE_NAME).slo 