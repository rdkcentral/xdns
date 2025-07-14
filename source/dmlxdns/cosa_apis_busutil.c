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

    module: dslh_dmagnt_exported.c

        For DSL Home Model Implementation (DSLH),
        BroadWay Service Delivery System

    ---------------------------------------------------------------

    description:

        This module implements the framework's exported functions
        by the Dslh DataModelAgent object;

        *   CosaGetParamValueUlong
        *   CosaGetParamValueString
        *   CosaGetInstanceNumberByIndex
        *   CosaGetInterfaceAddrByName

    ---------------------------------------------------------------

    environment:

        platform independent

    ---------------------------------------------------------------

    author:

        Bin Zhu

    ---------------------------------------------------------------

    revision:

        01/06/2011    initial revision.
        01/11/2011    added SLAP related apis.
        03/21/2011    added api to retrieve instance number by index

**********************************************************************/

#include "cosa_apis.h"

#include "plugin_main_apis.h"
#include "cosa_apis_busutil.h"
#include "ansc_platform.h"

extern void * g_pDslhDmlAgent;
/**********************************************************************

    prototype:

        ULONG
        CosaGetParamValueUlong2
            (
                char*                       pParamName
            )

    description:

        This function is called to retrieve a UONG value of a parameter;

    argument:
            char*                       pParamName
            The full name of the parameter;

    return:     the ULONG value;

**********************************************************************/
ULONG
CosaGetParamValueUlong
    (
        char*                       pParamName
    )
{
    /* we should look up CR to find right component.
            if it's P&M component, we just call the global variable
            Currently, we suppose all the parameter is from P&M. */

    return g_GetParamValueUlong(g_pDslhDmlAgent, pParamName);
}

/**********************************************************************

    prototype:

        int
        CosaGetParamValueString
            (
                char*                       pParamName,
                char*                       pBuffer,
                PULONG                      pulSize
            )

    description:

        This function is called to retrieve a string value of a parameter;

    argument:
            char*                       pParamName
            The full name of the parameter;

            char*                       pBuffer,
            The buffer for the value;

            PULONG                      pulSize
            The buffer of size;

    return:     0 = SUCCESS; -1 = FAILURE; 1 = NEW_SIZE;

**********************************************************************/
int
CosaGetParamValueString
    (
        char*                       pParamName,
        char*                       pBuffer,
        PULONG                      pulSize
    )
{
    /* we should look up CR to find right component.
            if it's P&M component, we just call the global variable
            Currently, we suppose all the parameter is from P&M. */


    return g_GetParamValueString(g_pDslhDmlAgent, pParamName, pBuffer, pulSize);

}

/**********************************************************************

    prototype:

        ULONG
        CosaGetInstanceNumberByIndex
            (
                char*                      pObjName,
                ULONG                      ulIndex
            );

    description:

        This function is called to retrieve the instance number specified by index;

    argument:   char*                      pObjName,
                The full object name;

                ULONG                      ulIndex
                The index specified;

    return:     the instance number;

**********************************************************************/
ULONG
CosaGetInstanceNumberByIndex
    (
        char*                      pObjName,
        ULONG                      ulIndex
    )
{
    /* we should look up CR to find right component.
            if it's P&M component, we just call the global variable
            Currently, we suppose all the parameter is from P&M. */


    return g_GetInstanceNumberByIndex(g_pDslhDmlAgent, pObjName, ulIndex);
}

char*
CosaGetInterfaceAddrByName
    (
        char*                      pInterfaceName
    )
{
    int ret = 0;
    int size = 0;
    char * dst_componentid =  NULL;
    char * dst_pathname    =  NULL;
    componentStruct_t ** ppComponents = NULL;
    char dst_pathname_cr[128] = {0};
    char * parameterNames[1];
    parameterValStruct_t ** parameterVal = NULL;
    char* pReturnName = NULL;

    if ( g_Subsystem[0] != 0 )
    {
        _ansc_sprintf(dst_pathname_cr, "%s%s", g_Subsystem, CCSP_DBUS_INTERFACE_CR);
    }
    else
    {
        _ansc_sprintf(dst_pathname_cr, "%s", CCSP_DBUS_INTERFACE_CR);
    }

    if ( !pInterfaceName || AnscSizeOfString(pInterfaceName) == 0 )
    {
        CcspTraceInfo(("Interface is NULL!\n"));

        goto EXIT2;
    }
    else
    {
        ret = CcspBaseIf_discComponentSupportingNamespace
            (
                g_MessageBusHandle,
                dst_pathname_cr,
                pInterfaceName,
                "",
                &ppComponents,
                &size
            );

        if ( ret == CCSP_SUCCESS )
        {
            /*
            printf("componentName:%s dbusPath:%s %s %s %d\n", ppComponents[0]->componentName, ppComponents[0]->dbusPath, ppComponents[0]->remoteCR_dbus_path,
                ppComponents[0]->remoteCR_name, ppComponents[0]->type );
                */
          dst_componentid = ppComponents[0]->componentName;
          ppComponents[0]->componentName = NULL;
          dst_pathname    = ppComponents[0]->dbusPath;
          ppComponents[0]->dbusPath = NULL;

          while( size )
          {
              if (ppComponents[size-1]->remoteCR_dbus_path)
                AnscFreeMemory(ppComponents[size-1]->remoteCR_dbus_path);

              if (ppComponents[size-1]->remoteCR_name)
                AnscFreeMemory(ppComponents[size-1]->remoteCR_name);

              if ( ppComponents[size-1]->componentName )
                AnscFreeMemory( ppComponents[size-1]->componentName );

              if ( ppComponents[size-1]->dbusPath )
                AnscFreeMemory( ppComponents[size-1]->dbusPath );

              AnscFreeMemory(ppComponents[size-1]);

              size--;
          }
        }
        else
        {
            CcspTraceError(("Can't find destination component.\n"));

            goto EXIT2;
        }

        parameterNames[0] = pInterfaceName;

        ret = CcspBaseIf_getParameterValues
                  (
                      g_MessageBusHandle,
                      dst_componentid,
                      dst_pathname,
                      parameterNames,
                      1,
                      &size ,
                      &parameterVal
                  );

        if ( ret == CCSP_SUCCESS && size == 1 )
        {
            pReturnName = AnscCloneString(parameterVal[0]->parameterValue);

            CcspTraceInfo(("CosaGetInterfaceAddrByName -- getParameterValues success, ready to free parameterVal...\n"));

            free_parameterValStruct_t(g_MessageBusHandle, size, parameterVal);

            goto EXIT1;
        }
        else
        {
            CcspTraceError(("CosaGetInterfaceAddrByName -- getParameterValues Error!\n"));

            goto EXIT2;
        }

    }

EXIT2:

    return AnscCloneString("::");

EXIT1:

    return pReturnName;
}


/**********************************************************************

    prototype:

        void *
        CosaGetRegistryRootFolder
           (
            )

    description:

        This function is called to retrieve RootFolder;

    argument:   
            char*                       pParamName
            The full name of the parameter;

    return:     the ULONG value;

**********************************************************************/
void *
CosaGetRegistryRootFolder
    (
    )
{
    return g_GetRegistryRootFolder(g_pDslhDmlAgent);
}

