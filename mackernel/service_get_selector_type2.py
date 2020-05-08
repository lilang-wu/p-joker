



"""
#get for UserClient->externalMethod()

IOExternalMethod * IOUserClient::
getTargetAndMethodForIndex(IOService **targetP, UInt32 index)
{
    IOExternalMethod *method = getExternalMethodForIndex(index);

    if (method)
        *targetP = (IOService *) method->object;

    return method;
}

example: IOAccelerationUserClient

IOExternalMethod *IOAccelerationUserClient::getTargetAndMethodForIndex(IOService **targetP, uint32_t index)
{
    IOAUC_START(getTargetAndMethodForIndex,index,0,0);
    static const IOExternalMethod methodTemplate[] =
    {
        /* 0 */  { NULL, (IOMethod) &IOAccelerationUserClient::extCreate,
                    kIOUCScalarIScalarO, 2, 1 },
        /* 1 */  { NULL, (IOMethod) &IOAccelerationUserClient::extDestroy,
                    kIOUCScalarIScalarO, 2, 0 },
    };

    if (index >= (sizeof(methodTemplate) / sizeof(methodTemplate[0])))
    {
        IOAUC_END(getTargetAndMethodForIndex,0,__LINE__,0);
        return NULL;
    }

    *targetP = this;
    IOAUC_END(getTargetAndMethodForIndex,0,0,0);
    return const_cast<IOExternalMethod *>(&methodTemplate[index]);
}

struct IOExternalMethod {
    IOService *		object;   //NULL
    IOMethod		func;     //function name
    IOOptionBits	flags;    //kIOUCScalarIScalarO or other
                                //the value of flags
                                enum {
                                    kIOUCTypeMask	= 0x0000000f,
                                    kIOUCScalarIScalarO = 0,
                                    kIOUCScalarIStructO = 2,
                                    kIOUCStructIStructO = 3,
                                    kIOUCScalarIStructI = 4,

                                    kIOUCForegroundOnly = 0x00000010,
                                };

    IOByteCount		count0;   //inputCount
    IOByteCount		count1;   //outputCount or inputStructCount, it depends on flags. such as kIOUCScalarIScalarO, or
                                //kIOUCScalarIStructureI
};




---------code in IOUserClient::externalMethod()
    if( !(method = getTargetAndMethodForIndex(&object, selector)) || !object )
            return (kIOReturnUnsupported);

        if (kIOUCForegroundOnly & method->flags)
        {
        if (task_is_gpu_denied(current_task()))
                return (kIOReturnNotPermitted);
        }

        switch (method->flags & kIOUCTypeMask)
        {
            case kIOUCScalarIStructI:
            err = shim_io_connect_method_scalarI_structureI( method, object,
                        args->scalarInput, args->scalarInputCount,
                        (char *) args->structureInput, args->structureInputSize );
            break;


---------code in shim_io_connect_method_scalarI_structureI
    if( inputCount != method->count0)
	{
	    IOLog("%s:%d %s: IOUserClient inputCount count mismatch 0x%llx 0x%llx\n", __FUNCTION__, __LINE__, object->getName(), (uint64_t)inputCount, (uint64_t)method->count0);
	    DTRACE_IO2(iokit_count_mismatch, uint64_t, (uint64_t)inputCount, uint64_t, (uint64_t)method->count0);
	    continue;
	}
	if( *outputCount != method->count1)
	{
	    IOLog("%s:%d %s: IOUserClient outputCount count mismatch 0x%llx 0x%llx\n", __FUNCTION__, __LINE__, object->getName(), (uint64_t)*outputCount, (uint64_t)method->count1);
	    DTRACE_IO2(iokit_count_mismatch, uint64_t, (uint64_t)*outputCount, uint64_t, (uint64_t)method->count1);
	    continue;
	}

	func = method->func;

	switch( inputCount) {


"""

