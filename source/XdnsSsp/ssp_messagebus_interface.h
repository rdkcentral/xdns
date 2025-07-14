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

    module: ssp_messagebus_interface.h

        For CCSP Secure Software Download

    ---------------------------------------------------------------

    description:

        The header file for the CCSP Message Bus Interface
        Service.

    ---------------------------------------------------------------

    environment:

        Embedded Linux

    ---------------------------------------------------------------

    author:

        Tom Chang

    ---------------------------------------------------------------

    revision:

        06/23/2011  initial revision.

**********************************************************************/

#ifndef  _SSP_MESSAGEBUS_INTERFACE_
#define  _SSP_MESSAGEBUS_INTERFACE_

ANSC_STATUS
ssp_XdnsMbi_MessageBusEngage
    (
        char * component_id,
        char * config_file,
        char * path
    );

int
ssp_XdnsMbi_Initialize
    (
        void * user_data
    );

int
ssp_XdnsMbi_Finalize
    (
        void * user_data
    );

int
ssp_XdnsMbi_Buscheck
    (
        void * user_data
    );

int
ssp_XdnsMbi_GetHealth
	(
		void
	);

int
ssp_XdnsMbi_FreeResources
    (
        int priority,
        void * user_data
    );

ANSC_STATUS
ssp_XdnsMbi_SendParameterValueChangeSignal
    (
        char * pPamameterName,
        SLAP_VARIABLE * oldValue,
        SLAP_VARIABLE * newValue,
        char * pAccessList
    );

ANSC_STATUS
ssp_XdnsMbi_SendTransferCompleteSignal
    (
        void
    );


/*
static DBusHandlerResult
path_message_func
    (
        DBusConnection  *conn,
        DBusMessage     *message,
        void            *user_data
    );
*/

ANSC_STATUS
ssp_XdnsMbi_RegisterToCR
    (
        ANSC_HANDLE                     hThisObject,
        name_spaceType_t*               pParameterArray
    );

void 
ssp_XdnsMbi_WaitConditionReady
	(
		void* 							bus_handle, 
		const char* 					dst_component_id,
		char* 							dbus_path,
		char*							src_component_id
	);

#endif
