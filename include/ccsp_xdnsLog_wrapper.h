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
#ifndef  _CCSP_HARVLOG_WRPPER_H_ 
#define  _CCSP_HARVLOG_WRPPER_H_

extern int consoleDebugEnable;
extern FILE* debugLogFile;

/*
 * Logging wrapper APIs g_Subsystem
 */
#define  CcspTraceBaseStr(arg ...)                                                                  \
            do {                                                                                    \
                snprintf(pTempChar1, 4095, arg);                                                    \
            } while (FALSE)


#define  CcspXdnsConsoleTrace(msg)                                                             \
{\
                char* pTempChar1 = (char*)malloc(4096);                                             \
                if ( pTempChar1 )                                                                   \
                {                                                                                   \
                    CcspTraceBaseStr msg;                                                           \
                    if(consoleDebugEnable)                                                          \
                    {\
                        fprintf(debugLogFile, "%s:%d: ", __FILE__, __LINE__);                       \
                        fprintf(debugLogFile, "%s", pTempChar1);                                    \
                        fflush(debugLogFile);                                                       \
                    }\
                    free(pTempChar1);                                                               \
                }\
}

#define  CcspXdnsTrace(msg)                                                                    \
{\
                char* pTempChar1 = (char*)malloc(4096);                                             \
                if ( pTempChar1 )                                                                   \
                {                                                                                   \
                    CcspTraceBaseStr msg;                                                           \
                    if(consoleDebugEnable)                                                          \
                    {\
                        fprintf(debugLogFile, "%s:%d: ", __FILE__, __LINE__); \
                        fprintf(debugLogFile, "%s", pTempChar1);                                    \
                        fflush(debugLogFile);                                                       \
                    }\
                    Ccsplog3("com.cisco.spvtg.ccsp.xdns", (pTempChar1));                            \
                    free(pTempChar1);                                                               \
                }\
}

#define  CcspXdnsEventTrace(msg)                                                               \
{\
                char* pTempChar1 = (char*)malloc(4096);                                             \
                if ( pTempChar1 )                                                                   \
                {                                                                                   \
                    CcspTraceBaseStr msg;                                                           \
                    if(consoleDebugEnable)                                                          \
                    {\
                        fprintf(debugLogFile, "%s:%d: ", __FILE__, __LINE__); \
                        fprintf(debugLogFile, "%s", pTempChar1);                                    \
                        fflush(debugLogFile);                                                       \
                    }\
                    Ccsplog3("com.cisco.spvtg.ccsp.xdns", (pTempChar1))                             \
                    free(pTempChar1);                                                               \
                }                                                                                   \
}


#endif
