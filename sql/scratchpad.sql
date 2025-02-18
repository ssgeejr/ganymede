select 
	a.ip as IP,
    b.port as Port,
    b.protocol as Protocol,
    b.service as Service
from landscape a,
	ports b
where
	a.landscape_id = b.landscape_id
order by a.landscape_id,b.port
	