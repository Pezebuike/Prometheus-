[Unit]
Description=Prometheus Node Exporter
Documentation=https://prometheus.io/docs/guides/node-exporter/
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=500
StartLimitBurst=5

[Service]
User={{ node_exporter_user }}
Group={{ node_exporter_group }}
Type=simple
Restart=on-failure
RestartSec=5s
ExecStart={{ node_exporter_binary_path }} {{ (node_exporter_service_args + node_exporter_extra_collectors | map('regex_replace', '^(.*)$', '--collector.\\1')) | join(' ') }}
ExecReload=/bin/kill -HUP $MAINPID
TimeoutStopSec=20s
SendSIGKILL=no
KillMode=mixed
SyslogIdentifier=node_exporter

# Security measures
{% for key, value in node_exporter_systemd_security.items() %}
{{ key }}={{ value }}
{% endfor %}

[Install]
WantedBy=multi-user.target