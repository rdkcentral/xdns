/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2016 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

/**********************************************************************
   Copyright [2014] [Cisco Systems, Inc.]
 
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
 
       http://www.apache.org/licenses/LICENSE-2.0
 
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**********************************************************************/


/**********************************************************************

    module:	cosa_dml_api_common.h

        For Data Model Library Implementation (DML),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This wrapper file defines the common data structure and
        constants for DML API.

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Ding Hua

    ---------------------------------------------------------------

    revision:

        12/15/2010    initial revision.

**********************************************************************/


#ifndef  _COSA_DML_API_COMMON_
#define  _COSA_DML_API_COMMON_

#include "ansc_platform.h"


/**********************************************************************
                STRUCTURE AND CONSTANT DEFINITIONS
**********************************************************************/

typedef  enum
_COSA_DML_IF_STATUS
{
    COSA_DML_IF_STATUS_Up               = 1,
    COSA_DML_IF_STATUS_Down,
    COSA_DML_IF_STATUS_Unknown,
    COSA_DML_IF_STATUS_Dormant,
    COSA_DML_IF_STATUS_NotPresent,
    COSA_DML_IF_STATUS_LowerLayerDown,
    COSA_DML_IF_STATUS_Error
}
COSA_DML_IF_STATUS, *PCOSA_DML_IF_STATUS;


typedef  struct
_COSA_DML_IF_STATS
{
    ULONG                           BytesSent;
    ULONG                           BytesReceived;
    ULONG                           PacketsSent;
    ULONG                           PacketsReceived;
    ULONG                           ErrorsSent;
    ULONG                           ErrorsReceived;
    ULONG                           UnicastPacketsSent;
    ULONG                           UnicastPacketsReceived;
    ULONG                           DiscardPacketsSent;
    ULONG                           DiscardPacketsReceived;
    ULONG                           MulticastPacketsSent;
    ULONG                           MulticastPacketsReceived;
    ULONG                           BroadcastPacketsSent;
    ULONG                           BroadcastPacketsReceived;
    ULONG                           UnknownProtoPacketsReceived;
}
COSA_DML_IF_STATS, *PCOSA_DML_IF_STATS;


typedef  enum
_COSA_DML_STATUS
{
    COSA_DML_STATUS_Disabled    = 1,
    COSA_DML_STATUS_Enabled,
    COSA_DML_STATUS_Error_Misconfigured,
    COSA_DML_STATUS_Error
}
COSA_DML_STATUS, *PCOSA_DML_STATUS;


#endif

