

"""
get from newUserClient: all we need is to parser the newUserClient, and find the "cmp rcx type"

x64 arguments order: rdi, rsi, rdx, rcx, r8, r9
rax: return value

kern_return_t
IOServiceOpen(
	io_service_t    service,
	task_port_t	owningTask,
	uint32_t	type,
	io_connect_t  *	connect )
{
    kern_return_t	kr;
    kern_return_t	result;

    kr = io_service_open_extended( service,
	owningTask, type, NDR_record, NULL, 0, &result, connect );

    if (KERN_SUCCESS == kr)
        kr = result;

    return (kr);
}

    --call--->

kern_return_t is_io_service_open_extended

    --call--->

IOReturn IOService::newUserClient( task_t owningTask, void * securityID,
                                    UInt32 type,  OSDictionary * properties,
                                    IOUserClient ** handler )

   --call--->

IOReturn IOService::newUserClient( task_t owningTask, void * securityID,
                                    UInt32 type, IOUserClient ** handler )
{
    return( kIOReturnUnsupported );
}


"""


import