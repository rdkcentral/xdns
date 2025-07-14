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


#ifndef  _SSP_GLOBAL_
#define  _SSP_GLOBAL_

#include <time.h>

#include "ansc_platform.h"
#include "slap_definitions.h"
#include "ansc_load_library.h"

#include "ccsp_message_bus.h"
#include "ccsp_base_api.h"
#include "ccsp_trace.h"

//#include "bbhm_co_oid.h"
//#include "bbhm_co_name.h"
//#include "bbhm_co_type.h"
//#include "bbhm_properties.h"

#include "ccsp_custom.h"

/*
#include "http_sco_interface.h"
#include "http_sco_exported_api.h"

#include "http_authco_interface.h"
#include "http_authco_exported_api.h"

#include "http_autho_interface.h"
#include "http_autho_exported_api.h"

#include "http_bmo_interface.h"
#include "http_bmo_exported_api.h"

#include "http_bmorep_interface.h"
#include "http_bmorep_exported_api.h"

#include "http_bmoreq_interface.h"
#include "http_bmoreq_exported_api.h"

#include "dslh_filemo_interface.h"
#include "dslh_filemo_exported_api.h"

#include "http_ifo_cas.h"

#include "download_mgr_interface.h"
#include "download_mgr_exported_api.h"
*/
#include "dslh_cpeco_interface.h"
#include "dslh_cpeco_exported_api.h"

#include "slap_vco_exported_api.h"
#include "ssp_messagebus_interface.h"

#include "dslh_ifo_mpa.h"
#include "dslh_dmagnt_interface.h"
#include "dslh_dmagnt_exported_api.h"
//#include "dslh_definitions_cwmp.h"

#include "ssp_internal.h"
#include "ssd_ifo_dml.h"
#include "ccsp_ifo_ccd.h"
#include "ccc_ifo_mbi.h"

//#include "ssd_ifo_gbi.h"

#include "messagebus_interface_helper.h"

/*
 *  Define custom trace module ID
 */
#ifdef   ANSC_TRACE_MODULE_ID
    #undef  ANSC_TRACE_MODULE_ID
#endif

#define  ANSC_TRACE_MODULE_ID                       ANSC_TRACE_ID_SSP

#endif
