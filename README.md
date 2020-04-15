# Sending Syslog via AMQP into Graylog

If your setup does not allow direct communication from all hosts to the Graylog Server or your Graylog Server is located inside a private Network you could use AMQP as Transport. You will need to have an AMQP Server like rabbitMQ reachable by all Hosts. But it's easy to secure this communication if transport is over an insecure wire. Forget more Information please read [the rabbitMQ SSL Guide](https://www.rabbitmq.com/ssl.html).

```
This Guide will not give you a complete copy&paste how-to,
but it will guide you and provide additional information.

Please do not follow the steps if you did not know how to deal
with common issues yourself.   
```


In this scenario a Syslog message will have the following stages:

- transformed into JSON by [rsyslog](http://www.rsyslog.com)
- send from rsyslog to [logstash](https://www.elastic.co/products/logstash) via TCP/UDP
- send from logstash to [rabbitMQ](https://www.rabbitmq.com)
- consumed by graylog from rabbitMQ
- Syslog extracted from JSON by Graylog

We will assume that you have a rabbitMQ running on **amqp.ext.example.org (203.0.113.2)** and your Graylog Instance is running on **graylog.int.example.org (192.168.0.10)**. Additional we have the Linux System **syslog.o1.example.org (198.51.100.1)** and **syslog.o2.example.org (192.0.2.1)** that will send Syslog Data. All Systems are running *ubuntu* so you might need to adjust some configuration path settings.

## prepare rabbitMQ
If no AMQP Broker is present, [install rabbitMQ](https://www.rabbitmq.com/install-debian.html) on **amqp.ext.example.org** and create a user for log delivery on CLI.

```
rabbitmqctl add_user my_rabbite_mq_user_here my_super_secure_password_rabbit_mq_password
rabbitmqctl set_permissions -p / my_rabbite_mq_user_here ".*" ".*" ".*"
```

If this Server is available *in the wild* please enable SSL  in your Setup. A Management GUI can be [installed with a few commands](https://www.rabbitmq.com/management.html) and an [admin User is Created ](http://stackoverflow.com/questions/22850546/cant-access-rabbitmq-web-management-interface-after-fresh-install) similar to the User creation above.
```
listeners.ssl.1 = 5671                  # this is the secure port for rabbitmq
#ssl_options.verify               = verify_peer
#ssl_options.fail_if_no_peer_cert = true
ssl_options.cacertfile           = /path/ssl/ca.crt
ssl_options.certfile             = /path/ssl/ssl/yourserver.crt
ssl_options.keyfile              = /path/ssl/yourserver.key
```


## send messages on rsyslog
With rsyslog, you can use templates to format how messages should look like. Formatting the messages direct at the source will help to have a clean message from the source to the destination.

To identify the messages with the Full Qualified Domain Name of the System that has created the message we use the Option ``PreserveFQDN`` - but you will need to have a clean working hostname resolution.

rsyslog will send the message via UDP to the local running logstash.

```
PreserveFQDN on
template(name="ls_json"
         type="list"
         option.json="on") {
           constant(value="{")
             constant(value="\"@timestamp\":\"")     property(name="timereported" dateFormat="rfc3339")
             constant(value="\",\"@version\":\"1")
             constant(value="\",\"message\":\"")     property(name="msg")
             constant(value="\",\"host\":\"")        property(name="hostname")
             constant(value="\",\"severity\":\"")    property(name="syslogseverity-text")
             constant(value="\",\"facility\":\"")    property(name="syslogfacility-text")
             constant(value="\",\"programname\":\"") property(name="programname")
             constant(value="\",\"procid\":\"")      property(name="procid")
           constant(value="\"}\n")
         }

*.* @127.0.0.1:5514;ls_json
```

The configuration above need to be placed inside the ``/etc/rsyslog.d/90-logstash.conf`` on **syslog.01.example.org** and **syslog.o2.example.org** in our example and rsyslog need to be restarted (``service rsyslog restart``).


## route messages with logstash
As of writing this, rsyslog was not able to send messages direct to AMQP on Ubuntu, so we need to use logstash for the transport.

Logstash will listen on *localhost* port *udp/5514* for the messages that are coming from rsyslog and forward them to the rabbitMQ Server.

```
input {
    UDP {
        port => 5514
        host => "127.0.0.1"
        type => syslog
        codec => "json"
        }
}

filter {
  # This replaces the host field (UDP source) with the host that generated the message (sysloghost)
  if [sysloghost] {
      mutate {
          replace => [ "host", "%{sysloghost}" ]
          remove_field => "sysloghost" # prune the field after successfully replacing "host"
        }
      }
}

output {
    rabbitmq {
      exchange => "log-messages"
        exchange_type => "fanout"
        key => "log-messages"
        host => "amqp.ext.example.org"
        durable => true
        persistent => true
        port => 5672
        user => "my_rabbite_mq_user_here"
        password => "my_super_secure_password_rabbit_mq_password"
        verify_ssl => true  # we assume that you have a valid certificate!
      }
    }
```

## consume messages with graylog
Now the Data need to be consumed by graylog. Create an [input](http://docs.graylog.org/en/2.0/pages/getting_started/config_input.html) with the Input *Syslog AMQP*. Add the Information that is configured in the former steps (exchange, username, password, hostname). Set the Option *Allow overwrite date*.

Start the Input to consume the first messages and create [a JSON extractor](http://docs.graylog.org/en/2.0/pages/extractors.html#using-the-json-extractor). Additional create a second extractor on the field `host` and the type `copy input` and store it in the field `source`. You might want a third `copy input` to store `@timestamp` in `timestamp`.

## what's next?
Use the *rsyslog* Systems as Syslog Proxies for every possible source in the same network, add more systems to your setup.


# Credits
- untergeek for [rsyslog / json template](https://gist.github.com/untergeek/0373ee85a41d03ae1b78) and the [blogpost](http://untergeek.com/2012/10/11/using-rsyslog-to-send-pre-formatted-json-to-logstash/)
- IETF for [documentation ips](https://tools.ietf.org/html/rfc5737)
- StackOverflow User Gabriele for the answer [how to create User on CLI](http://stackoverflow.com/questions/22850546/cant-access-rabbitmq-web-management-interface-after-fresh-install)
