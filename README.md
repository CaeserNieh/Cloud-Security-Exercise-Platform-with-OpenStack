OpenStack neutronclient SDK 學習
(https://my.oschina.net/alazyer/blog/737942)
===

```python=
networks = neutron.list_networks()
"""
{
	'networks': [
{
            u'admin_state_up': True,
            u'id': u'd6e83c1b-1b16-470d-8006-18ee19f6dafe',
            u'mtu': 0,
            u'name': u'ext-net',
            u'provider:network_type': u'flat',
            u'provider:physical_network': u'external',
            u'provider:segmentation_id': None,
            u'router:external': True,
            u'shared': True,
            u'status': u'ACTIVE',
            u'subnets': [u'3ee3f602-86cc-44e9-8fd3-1ecd454760da'],
            u'tenant_id': u'65f273a79a834498a87f3c51bd35bebf'
        },
        {
            u'admin_state_up': True,
            u'id': u'd6e83c1b-1b16-470d-8006-18ee19f6dafe',
            u'mtu': 0,
            u'name': u'ext-net',
            u'provider:network_type': u'flat',
            u'provider:physical_network': u'external',
            u'provider:segmentation_id': None,
            u'router:external': True,
            u'shared': True,
            u'status': u'ACTIVE',
            u'subnets': [u'3ee3f602-86cc-44e9-8fd3-1ecd454760da'],
            u'tenant_id': u'65f273a79a834498a87f3c51bd35bebf'
        },
    ]
}
"""

# 依据設定條件過慮，return是搜尋實例
# 例如，依据provider:physical_network属性来过滤所有可以通外网的network
filters = {}
filters["provider:physical_network"] = "external"
networks = neutron.list_networks(**filters)
```

------------
創建network

```python=
body_data = {
    'network': {
        "name": "test_creating_network",
        "admin_state_up": True
        "router:external": True,
        "provider:physical_network": "external",
        "provider:network_type": "flat",
    }
}

netw = neutron.create_network(body=body_data)
"""
{
    "network": {
        "status": "ACTIVE",
        "subnets": [],
        "name": "net1",
        "admin_state_up": true,
        "tenant_id": "9bacb3c5d39d41a79512987f338cf177",
        "router:external": True,
        "provider:physical_network": "external",
        "provider:network_type": "flat",
        "segments": [
            {
                "provider:segmentation_id": 2,
                "provider:physical_network": "8bab8453-1bc9-45af-8c70-f83aa9b50453",
                "provider:network_type": "vlan"
            },
            {
                "provider:segmentation_id": null,
                "provider:physical_network": "8bab8453-1bc9-45af-8c70-f83aa9b50453",
                "provider:network_type": "stt"
            }
        ],
        "shared": false,
        "id": "4e8e5957-649f-477b-9e5b-f1f75b21c03c"
    }
}
"""
```

-----------
刪除network
```python=
body_data = {
    'network': {
        "name": "test_creating_network",
        "admin_state_up": True
        "router:external": True,
        "provider:physical_network": "external",
        "provider:network_type": "flat",
    }
}

netw = neutron.create_network(body=body_data)
net_dict = netw['network']
network_id = net_dict['id']
neutron.delete_network(network_id)
```
-------
更新network

```python=
body_data = {
    'network': {
        "name": "test_creating_network_renew",
    }
}

netw = neutron.update_network(network_id, body=body_data)
```

------
查詢所有subnet

```python=
subnets = neutron.list_subnets()
"""
{
    "subnets": [
        {
            "name": "private-subnet",
            "enable_dhcp": true,
            "network_id": "db193ab3-96e3-4cb3-8fc5-05f4296d0324",
            "tenant_id": "26a7980765d0414dbc1fc1f88cdb7e6e",
            "dns_nameservers": [],
            "allocation_pools": [
                {
                    "start": "10.0.0.2",
                    "end": "10.0.0.254"
                }
            ],
            "host_routes": [],
            "ip_version": 4,
            "gateway_ip": "10.0.0.1",
            "cidr": "10.0.0.0/24",
            "id": "08eae331-0402-425a-923c-34f7cfe39c1b"
        },
        {
            "name": "my_subnet",
            "enable_dhcp": true,
            "network_id": "d32019d3-bc6e-4319-9c1d-6722fc136a22",
            "tenant_id": "4fd44f30292945e481c7b8a0c8908869",
            "dns_nameservers": [],
            "allocation_pools": [
                {
                    "start": "192.0.0.2",
                    "end": "192.255.255.254"
                }
            ],
            "host_routes": [],
            "ip_version": 4,
            "gateway_ip": "192.0.0.1",
            "cidr": "192.0.0.0/8",
            "id": "54d6f61d-db07-451c-9ab3-b9609b6b6f0b"
        }
    ]
}
"""
```

-------
建立subnet

```python=
start = '192.168.199.2'
end = '192.168.199.254'
allocation_pools = {'start': start, 'end': end}
gateway_ip = '192.168.199.1'

body_data = {
    'subnets':{
        'network_id': network_id,
        'cidr': '192.168.199.0/24',
        'ip_version': 4,
        "enable_dhcp": False,
        "allocation_pools": allocation_pools,
        "gateway_ip": gateway_ip,
    }
}

updated = neutron.update_subnet(subnet_id, body=body_data)

ret = neutron.create_subnet(body=body_data)
"""
{
    "subnet": {
        "name": "",
        "enable_dhcp": false,
        "network_id": "d32019d3-bc6e-4319-9c1d-6722fc136a22",
        "tenant_id": "4fd44f30292945e481c7b8a0c8908869",
        "dns_nameservers": [],
        "allocation_pools": [
            {
                "start": "192.168.199.2",
                "end": "192.168.199.254"
            }
        ],
        "host_routes": [],
        "ip_version": 4,
        "gateway_ip": "192.168.199.1",
        "cidr": "192.168.199.0/24",
        "id": "3b80198d-4f7b-4f77-9ef5-774d54e17126"
    }
}
"""
```

--------
查詢所有port 

```python=
neutron.list_port()
"""
{
    "ports": [
        {
            "status": "ACTIVE",
            "name": "",
            "allowed_address_pairs": [],
            "admin_state_up": true,
            "network_id": "70c1db1f-b701-45bd-96e0-a313ee3430b3",
            "tenant_id": "",
            "extra_dhcp_opts": [],
            "device_owner": "network:router_gateway",
            "mac_address": "fa:16:3e:58:42:ed",
            "fixed_ips": [
                {
                    "subnet_id": "008ba151-0b8c-4a67-98b5-0d2b87666062",
                    "ip_address": "172.24.4.2"
                }
            ],
            "id": "d80b1a3b-4fc1-49f3-952e-1e2ab7081d8b",
            "security_groups": [],
            "device_id": "9ae135f4-b6e0-4dad-9e91-3c223e385824"
        },
        {
            "status": "ACTIVE",
            "name": "",
            "allowed_address_pairs": [],
            "admin_state_up": true,
            "network_id": "f27aa545-cbdd-4907-b0c6-c9e8b039dcc2",
            "tenant_id": "d397de8a63f341818f198abb0966f6f3",
            "extra_dhcp_opts": [],
            "device_owner": "network:router_interface",
            "mac_address": "fa:16:3e:bb:3c:e4",
            "fixed_ips": [
                {
                    "subnet_id": "288bf4a1-51ba-43b6-9d0a-520e9005db17",
                    "ip_address": "10.0.0.1"
                }
            ],
            "id": "f71a6703-d6de-4be1-a91a-a570ede1d159",
            "security_groups": [],
            "device_id": "9ae135f4-b6e0-4dad-9e91-3c223e385824"
        }
    ]
}
"""
```

