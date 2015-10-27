/*
 * Copyright 2013 FuseLogic BV
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
package nl.fuselogic.robotframework.libraries.oim;


import Thor.API.Exceptions.tcAPIException;
import Thor.API.Exceptions.tcColumnNotFoundException;
import Thor.API.Exceptions.tcInvalidAttributeException;
import Thor.API.Exceptions.tcInvalidLookupException;
import Thor.API.Exceptions.tcInvalidValueException;
import Thor.API.Operations.tcAccessPolicyOperationsIntf;
import Thor.API.Operations.tcLookupOperationsIntf;
import Thor.API.Security.XLClientSecurityAssociation;
import Thor.API.tcResultSet;
import com.thortech.xl.dataaccess.tcDataBaseClient;
import com.thortech.xl.dataaccess.tcDataProvider;
import com.thortech.xl.dataaccess.tcDataSetException;
import com.thortech.xl.dataobj.tcDataSet;

import java.io.InputStream;

import java.sql.Timestamp;
import java.text.ParseException;

import java.text.SimpleDateFormat;
import java.util.Calendar;

import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;

import javax.security.auth.login.LoginException;
import oracle.iam.accesspolicy.api.AccessPolicyServiceInternal;
import oracle.iam.accesspolicy.exception.AccessPolicyEvaluationException;
import oracle.iam.accesspolicy.exception.AccessPolicyEvaluationUnauthorizedException;
import oracle.iam.accesspolicy.exception.AccessPolicyServiceException;
import oracle.iam.accesspolicy.exception.UserNotActiveException;
import oracle.iam.configservice.api.ConfigManager;
import oracle.iam.configservice.api.Constants;
import oracle.iam.configservice.exception.ConfigManagerException;
import oracle.iam.configservice.exception.NoSuchAttributeException;
import oracle.iam.configservice.vo.AttributeDefinition;
import oracle.iam.identity.exception.NoSuchRoleException;
import oracle.iam.identity.exception.NoSuchUserException;
import oracle.iam.identity.exception.RoleDeleteException;
import oracle.iam.identity.exception.RoleModifyException;

import oracle.iam.identity.exception.RoleSearchException;
import oracle.iam.identity.exception.SearchKeyNotUniqueException;
import oracle.iam.identity.exception.UserDeleteException;
import oracle.iam.identity.exception.UserDisableException;
import oracle.iam.identity.exception.UserLookupException;
import oracle.iam.identity.exception.UserManagerException;
import oracle.iam.identity.exception.UserModifyException;
import oracle.iam.identity.exception.UserSearchException;
import oracle.iam.identity.exception.ValidationFailedException;
import oracle.iam.identity.rolemgmt.api.RoleManager;
import oracle.iam.identity.rolemgmt.api.RoleManagerConstants;
import oracle.iam.identity.rolemgmt.vo.Role;
import oracle.iam.identity.usermgmt.api.UserManager;
import oracle.iam.identity.usermgmt.api.UserManagerConstants;
import oracle.iam.identity.usermgmt.vo.User;
import oracle.iam.platform.OIMClient;
import oracle.iam.platform.authz.exception.AccessDeniedException;
import oracle.iam.platform.context.ContextAwareString;
import oracle.iam.platform.context.ContextManager;
import oracle.iam.platform.entitymgr.vo.SearchCriteria;
import oracle.iam.provisioning.api.ApplicationInstanceService;
import oracle.iam.provisioning.api.ProvisioningConstants;
import oracle.iam.provisioning.api.ProvisioningService;
import oracle.iam.provisioning.exception.AccountNotFoundException;
import oracle.iam.provisioning.exception.ApplicationInstanceNotFoundException;
import oracle.iam.provisioning.exception.GenericAppInstanceServiceException;
import oracle.iam.provisioning.exception.GenericProvisioningException;
import oracle.iam.provisioning.exception.UserNotFoundException;
import oracle.iam.provisioning.vo.Account;
import oracle.iam.provisioning.vo.ApplicationInstance;
import oracle.iam.provisioning.vo.EntitlementInstance;
import oracle.iam.scheduler.api.SchedulerService;
import oracle.iam.scheduler.exception.IncorrectScheduleTaskDefinationException;
import oracle.iam.scheduler.exception.LastModifyDateNotSetException;
import oracle.iam.scheduler.exception.NoJobHistoryFoundException;
import oracle.iam.scheduler.exception.ParameterValueTypeNotSupportedException;
import oracle.iam.scheduler.exception.RequiredParameterNotSetException;
import oracle.iam.scheduler.exception.SchedulerAccessDeniedException;
import oracle.iam.scheduler.exception.SchedulerException;
import oracle.iam.scheduler.vo.JobDetails;
import oracle.iam.scheduler.vo.JobHistory;
import oracle.iam.scheduler.vo.JobParameter;
import oracle.iam.scheduler.vo.ScheduledTask;
import oracle.iam.selfservice.self.selfmgmt.api.AuthenticatedSelfService;

import org.robotframework.javalib.annotation.ArgumentNames;
import org.robotframework.javalib.annotation.RobotKeyword;
import org.robotframework.javalib.annotation.RobotKeywordOverload;
import org.robotframework.javalib.annotation.RobotKeywords;
import org.robotframework.javalib.library.AnnotationLibrary;


@RobotKeywords
public class OimClientLibrary extends AnnotationLibrary {
   
    public static final String ROBOT_LIBRARY_VERSION = "0.2";
   
    private static enum JobStatus { SHUTDOWN, STARTED, STOPPED, NONE, PAUSED, RUNNING, FAILED, INTERRUPT }
    
    private static enum ProcessStatus { WAITING,  ABANDONED,  COMPLETED,  MANUAL_COMPLETED,  ACTIVE,  FAILED,  CANCELLED,  PENDING_CANCELLED,  PENDING_CANCELLED_WITH_COMPENSATION,  CANCELLED_WITH_COMPENSATION,  COMPENSATED,  RESTARTED }
   
    private OIMClient oimClient;
    private String oimUrl;
    
    private static SimpleDateFormat timestampDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
    
    private static String LOOKUP_ENCODE_NAME= "Lookup Definition.Lookup Code Information.Code Key";
    private static String LOOKUP_DECODE_NAME= "Lookup Definition.Lookup Code Information.Decode";
    
    private static int maxWaitSeconds = 1800;
   
    public OimClientLibrary(List<String> list) {
        super(list);
    }
 
    public OimClientLibrary(String string) {
        super(string);
    }
 
    public OimClientLibrary() {
        super("nl/fuselogic/robotframework/libraries/oim/*.class");
    }
   
    @Override
    public String getKeywordDocumentation(String keywordName) {
        if (keywordName.equals("__intro__") || keywordName.equals("__init__")) {
            InputStream in = this.getClass().getResourceAsStream(keywordName + ".txt");
            Scanner s = new java.util.Scanner(in).useDelimiter("\\A");
            return s.hasNext() ? s.next() : "";
        }
        return super.getKeywordDocumentation(keywordName);
    }
    
    @RobotKeyword("Adds an entry having encode value _encode_ and decode value _decode_ to the lookup identified by _lookupcode_.")
    @ArgumentNames({"lookupcode","encode","decode"})
    public void addOimLookupValue(String lookupcode, String encode, String decode) throws tcAPIException, tcInvalidLookupException, tcInvalidValueException {
        if (oimClient == null) {
            throw new RuntimeException("There is no connection to OIM");
        }
        tcLookupOperationsIntf lookupIntf = oimClient.getService(tcLookupOperationsIntf.class);
        
        lookupIntf.addLookupValue(lookupcode, encode, decode, null, null);
    }
   
    @RobotKeyword("Make a connection to OIM")
    @ArgumentNames({"username", "password", "url", "warnonreconnect="})
    public synchronized void connectToOim(String username, String password, String url, Boolean warnonreconnect) throws LoginException {
        
        String reconnectLogLevel = (warnonreconnect) ? "*WARN*":"*INFO*";
        
        if(oimClient != null) {
            if(!this.oimUrl.equals(url)) {
                System.out.println(reconnectLogLevel+" There is already a connection to OIM at url "+this.oimUrl+". Going to reconnect to "+url+".");
            } else {
                try {
                    // Check if connection is still valid by getting user details
                    AuthenticatedSelfService authenticatedSelfService = oimClient.getService(AuthenticatedSelfService.class);
                    Set<String> retAttrs = new HashSet<String>();
                    retAttrs.add(UserManagerConstants.AttributeName.USER_LOGIN.getId());
                    User user = authenticatedSelfService.getProfileDetails(retAttrs);

                    if(user.getLogin().equalsIgnoreCase(username)) {
                        System.out.println("*INFO* There is already a connection to OIM");
                        return;
                    } else {
                        System.out.println(reconnectLogLevel+" There is already a connection to OIM as user "+user.getLogin()+". Going to reconnect as user "+username+".");
                    }
                } catch (Exception e) {
                    System.out.println("*TRACE* Got exception "+e.getClass().getName()+ ". Message: " +e.getMessage());
                    System.out.println(reconnectLogLevel+" There is already a connection to OIM, but it might be stale. Going to reconnect as user "+username+".");
                }
            }
        }
        
        System.out.println("*INFO* Connecting to "+url+" as "+username);
        
        oimUrl = url;
        
        Hashtable env = new Hashtable();
        env.put(OIMClient.JAVA_NAMING_FACTORY_INITIAL, OIMClient.WLS_CONTEXT_FACTORY);
        env.put(OIMClient.JAVA_NAMING_PROVIDER_URL, url);
       
        oimClient = new OIMClient(env);
        oimClient.login(username, password.toCharArray());
        
        XLClientSecurityAssociation.setClientHandle(oimClient);
    }
    
    @RobotKeywordOverload
    public synchronized void connectToOim(String username, String password, String url) throws LoginException {
        connectToOim(username, password, url, true);
    }
   
    @RobotKeyword("Disconnect from OIM")
    public synchronized void disconnectFromOim() {
        if (oimClient == null) {
            System.out.println("*WARN* There is no connection to OIM");
            return;
        }
        
        try {
            oimClient.logout();
        } catch (Exception e) {
            System.out.println("*WARN* Caught exception during OIM logout: "+e.getMessage());
        }
        
        oimClient = null;
    }
    
    @RobotKeyword("Fails if specified account does not have specified entitlement.\n\n" +
                    "Example:\n" +
                    "| Oim Account Should Have Entitlement | ${accountid} | UD_DUM_ENT | Write |\n" +
                    "See `Get Oim Account` how to obtain an accountid.")
    @ArgumentNames({"accountid","childform","entitlement"})
    public void oimAccountShouldHaveEntitlement(String accountid, String childform, String entitlement) throws AccountNotFoundException,
                                                                    GenericProvisioningException, UserNotFoundException {
        EntitlementInstance entitlementInstance = searchEntitlementInstance(accountid, childform, entitlement);
        
        if(entitlementInstance == null) {
            throw new RuntimeException("No entitlement instance found in OIM matching: accountid="+accountid+", childform="+childform+", entitlement="+entitlement);
        }
    }
    
    @RobotKeyword("Fails if specified account has specified entitlement. See `Oim Account Should Have Entitlement` for more information on usage.")
    @ArgumentNames({"accountid","childform","entitlement"})
    public void oimAccountShouldNotHaveEntitlement(String accountid, String childform, String entitlement) throws AccountNotFoundException,
                                                                    GenericProvisioningException, UserNotFoundException {
        EntitlementInstance entitlementInstance = searchEntitlementInstance(accountid, childform, entitlement);
        
        if(entitlementInstance != null) {
            throw new RuntimeException("Entitlement instance found in OIM matching: accountid="+accountid+", childform="+childform+", entitlement="+entitlement);
        }
    }
    
    @RobotKeyword(  "Deletes specified role in OIM. See `Get Oim Role` how to obtain a ${rolekey}.")
    @ArgumentNames({"rolekey"})
    public void deleteOimRole(String rolekey) throws ValidationFailedException, AccessDeniedException, RoleDeleteException, NoSuchRoleException {
        if (oimClient == null) {
            throw new RuntimeException("There is no connection to OIM");
        }
        
        RoleManager roleManager = oimClient.getService(RoleManager.class);
        
        System.out.println("*INFO* Deleting role "+rolekey);
        
        roleManager.delete(rolekey);
    }
    
    @RobotKeyword(  "Deletes specified user in OIM.\n\n"+
                    "Set _force_ to True if immediate deletion is required, even if OIM system property _XL.UserDeleteDelayPeriod_ is set to a non-zero value. If mentioned system property is set to zero,  _force_  has no effect: the deletion will always be immediate.\n\n"+
                    "See `Get Oim User` how to obtain a ${usrkey}.")
    @ArgumentNames({"usrkey","force="})
    public void deleteOimUser(String usrkey, boolean force) throws ValidationFailedException, AccessDeniedException, UserModifyException, NoSuchUserException, UserDeleteException, UserDisableException, UserLookupException {
        if (oimClient == null) {
            throw new RuntimeException("There is no connection to OIM");
        }
        
        UserManager userManager = oimClient.getService(UserManager.class);
        
        System.out.println("*INFO* Deleting user "+usrkey);
        
        if(force) {
            User user = userManager.getDetails(usrkey, null, false);
            
            System.out.println("*INFO* Bypassing any delayed delete configuration in OIM");
            
            if(!user.getStatus().equals(UserManagerConstants.AttributeValues.USER_STATUS_DISABLED.getId())) {
                userManager.disable(usrkey, false);
            }
            
            Calendar cal = Calendar.getInstance();
            cal.set(Calendar.HOUR_OF_DAY, 0);
            cal.set(Calendar.MINUTE, 0);
            cal.set(Calendar.SECOND, 0);
            cal.set(Calendar.MILLISECOND, 0);
            
            User userModify = new User(usrkey);
            userModify.setAttribute(UserManagerConstants.AttributeName.AUTOMATICALLY_DELETED_ON.getId(), cal.getTime());
            userManager.modify(userModify);
            
            // UserManager API delete operation will only execute a delayed delete
            // if context parameter "operationinitiator" is set to "scheduler".
            ContextManager.pushContext(null, ContextManager.ContextTypes.ADMIN, null);
            ContextManager.setValue("operationinitiator", new ContextAwareString("scheduler"), true);
        }
        
        userManager.delete(usrkey, false);
        
        if (force) {
            ContextManager.popContext();
        }
    }
    
    @RobotKeywordOverload
    public void deleteOimUser(String usrkey) throws ValidationFailedException, AccessDeniedException, UserModifyException, NoSuchUserException, UserDeleteException, UserDisableException, UserLookupException {
        deleteOimUser(usrkey, false);
    }
    
    @RobotKeyword("Returns true if specified role is present in OIM, false otherwise. See `Get Oim Role` for more information on usage.")
    @ArgumentNames({"rolesearchattributes"})
    public boolean doesOimRoleExist(HashMap<String, String> rolesearchattributes) throws AccessDeniedException, RoleSearchException, NoSuchAttributeException, ConfigManagerException, ParseException {
       
        List<Role> roles = searchRoles(rolesearchattributes);
       
        if(roles.isEmpty()) {
            return false;
        } else if(roles.size() == 1) {
            return true;
        } else {
            throw new RuntimeException("Multiple roles in OIM match '"+rolesearchattributes.toString()+"'");
        }
    }
    
    @RobotKeyword("Returns true if specified user is present in OIM, false otherwise. See `Get Oim User` for more information on usage.")
    @ArgumentNames({"usersearchattributes"})
    public boolean doesOimUserExist(HashMap<String, String> usersearchattributes) throws AccessDeniedException, UserSearchException, NoSuchAttributeException, ConfigManagerException, ParseException {
       
        List<User> users = searchUsers(usersearchattributes);
       
        if(users.isEmpty()) {
            return false;
        } else if(users.size() == 1) {
            return true;
        } else {
            throw new RuntimeException("Multiple users in OIM match '"+usersearchattributes.toString()+"'");
        }
    }
    
    @RobotKeyword("Waits for all orchestration processes identified by the (all optional) keyword arguments to finish.\n\n" +
        "Optional argument _entityid_ specifies the OIM internal key of the entity. For example a usr_key or ugp_key, depending on the _entitytype_.\n\n" +
        "Optional argument _entitytype_ specifies the type of OIM entity. For example 'User', 'Role', 'RoleUser', etc.\n\n" +
        "Optional argument _operation_ specifies the OIM operation. For example 'CREATE', 'MODIFY', 'DELETE', etc.\n\n" +
        "Optional argument _createdafter_ specifies a timestamp on or after which the orchestration(s) must have started. The format must be _yyyy-MM-dd HH:mm:ss.SSS_.\n\n" +
        "Optional argument _createdbefore_ specifies a timestamp on or before which the orchestration(s) must have started. The format must be _yyyy-MM-dd HH:mm:ss.SSS_.\n\n" +
        "Examples:\n" +
        "| Wait For Oim Orchestrations To Complete | | | | # Wait for all orchestration to finish (this is probably not what you want to use, especially on a busy system) |\n" +
        "| Wait For Oim Orchestrations To Complete | entityid=${usrkey} | entitytype=User | | # Wait for all orchestrations regarding user with key ${usrkey} to finish |\n" +
        "| Wait For Oim Orchestrations To Complete | entityid=${usrkey} | entitytype=User | operation=CREATE | # Wait for all orchestrations regarding creation of user with key ${usrkey} to finish |\n" +
        "| |\n" +
        "| ${now}= | Get Current Date |\n" +
        "| ${one minute ago}= | Get Current Date | increment=- 1 minute |\n" +
        "| Wait For Oim Orchestrations To Complete | createdbefore=${now} | | | # Wait for all orchestration created until now to finish |\n" +
        "| Wait For Oim Orchestrations To Complete | createdafter=${one minute ago} | createdbefore=${now} | | # Wait for all orchestration created in the last minute to finish |\n" +
        "| Wait For Oim Orchestrations To Complete | entityid=${usrkey} | entitytype=User | createdafter=${one minute ago} | # Wait for all orchestration created in the last minute regarding user with key ${usrkey} to finish |\n" +
        "See `Get Oim User` how to obtain _usrkey_.")
    @ArgumentNames({"entityid=", "entitytype=", "operation=", "createdafter=", "createdbefore="})
    public void waitForOimOrchestrationsToComplete(String entityId, String entityType, String operation, String createdAfter, String createdBefore) throws tcDataSetException, InterruptedException {
        if (oimClient == null) {
            throw new RuntimeException("There is no connection to OIM");
        }
        
        if(entityId != null && entityId.isEmpty()) {
            entityId = null;
        }
        if(entityType != null && entityType.isEmpty()) {
            entityType = null;
        }
        if(operation != null && operation.isEmpty()) {
            operation = null;
        }
        if(createdAfter != null && createdAfter.isEmpty()) {
            createdAfter = null;
        }
        if(createdBefore != null && createdBefore.isEmpty()) {
            createdBefore = null;
        }
        
        String orchprocessQuery = "SELECT id, status FROM orchprocess";
        
        if(entityId != null || entityType != null || operation != null || createdAfter != null || createdBefore != null) {
            orchprocessQuery = orchprocessQuery + " START WITH 1=1";
            
            if(entityId != null) {
                orchprocessQuery = orchprocessQuery + " AND entityid='" + entityId + "'";
            }
            if(entityType != null) {
                orchprocessQuery = orchprocessQuery + " AND entitytype='" + entityType + "'";
            }
            if(operation != null) {
                orchprocessQuery = orchprocessQuery + " AND operation='" + operation + "'";
            }
            if(createdAfter != null) {
                orchprocessQuery = orchprocessQuery + " AND createdon >= TO_TIMESTAMP('" + createdAfter + "', 'YYYY-MM-DD HH24:MI:SS.FF')";
            }
            if(createdBefore != null) {
                orchprocessQuery = orchprocessQuery + " AND createdon <= TO_TIMESTAMP('" + createdBefore + "', 'YYYY-MM-DD HH24:MI:SS.FF')";
            }
            
            orchprocessQuery = orchprocessQuery + " CONNECT BY PRIOR id = parentprocessid";
        }
        
        tcDataProvider dbProvider = new tcDataBaseClient();
        tcDataSet dataSet = new tcDataSet();
        
        System.out.println("*INFO* Waiting for any orchestration processes to show up");
        System.out.println("*TRACE* Constructed SQL query: "+orchprocessQuery);
        
        dataSet.setQuery(dbProvider, orchprocessQuery);
        dataSet.executeQuery();
        int waited = 0;
        while (dataSet.getTotalRowCount() == 0) {
            if(waited == maxWaitSeconds) {
                throw new RuntimeException("Maximum waiting time of " + maxWaitSeconds + " seconds reached");
            }

            Thread.sleep(1000); // 1 second
            waited++;
            dataSet.refresh();
        }
        
        String activeOrchprocessQuery = "SELECT * FROM (" + orchprocessQuery + ") WHERE status IN ('" + ProcessStatus.WAITING.name() + "', '" + ProcessStatus.ACTIVE.name() + "', '" + ProcessStatus.PENDING_CANCELLED.name() + "', '" + ProcessStatus.PENDING_CANCELLED_WITH_COMPENSATION.name() + "')";
        
        System.out.println("*INFO* Waiting for the orchestration processes to finish");
        System.out.println("*TRACE* Constructed SQL query: "+activeOrchprocessQuery);
        dataSet.setQuery(dbProvider, activeOrchprocessQuery);
        dataSet.executeQuery();
        while (dataSet.getTotalRowCount() != 0) {
            System.out.println("*TRACE* Number of active orchestration processes found: "+dataSet.getTotalRowCount());
            
            if(waited == maxWaitSeconds) {
                throw new RuntimeException("Maximum waiting time of " + maxWaitSeconds + " seconds reached");
            }
            
            Thread.sleep(1000); // 1 second
            waited++;
            dataSet.refresh();
        }
    }
    
    @RobotKeywordOverload
    public void waitForOimOrchestrationsToComplete(String entityId, String entityType, String operation, String createdAfter) throws tcDataSetException, InterruptedException {
        waitForOimOrchestrationsToComplete(entityId, entityType, operation, createdAfter, null);
    }
    
    @RobotKeywordOverload
    public void waitForOimOrchestrationsToComplete(String entityId, String entityType, String operation) throws tcDataSetException, InterruptedException {
        waitForOimOrchestrationsToComplete(entityId, entityType, operation, null, null);
    }
    
    @RobotKeywordOverload
    public void waitForOimOrchestrationsToComplete(String entityId, String entityType) throws tcDataSetException, InterruptedException {
        waitForOimOrchestrationsToComplete(entityId, entityType, null, null, null);
    }
    
    @RobotKeywordOverload
    public void waitForOimOrchestrationsToComplete(String entityId) throws tcDataSetException, InterruptedException {
        waitForOimOrchestrationsToComplete(entityId, null, null, null, null);
    }
    
    @RobotKeywordOverload
    public void waitForOimOrchestrationsToComplete() throws tcDataSetException, InterruptedException {
        waitForOimOrchestrationsToComplete(null, null, null, null, null);
    }
    
    @RobotKeyword("Evaluates the access policies for the user specified by _usrkey_.\n\n" +
        "This keyword returns when the evaluation process in OIM has completed.\n\n" +
        "See `Get Oim User` how to obtain _usrkey_.")
    @ArgumentNames({"usrkey"})
    public void evaluateOimAccessPoliciesForUser(String usrKey) throws NoSuchUserException, UserNotActiveException, AccessPolicyEvaluationUnauthorizedException, AccessPolicyServiceException, AccessPolicyEvaluationException, tcDataSetException, InterruptedException {
        if (oimClient == null) {
            throw new RuntimeException("There is no connection to OIM");
        }
        
        tcDataProvider dbProvider = new tcDataBaseClient();
        tcDataSet dataSet = new tcDataSet();
        
        dataSet.setQuery(dbProvider, "SELECT * FROM user_provisioning_attrs WHERE usr_key = "+usrKey+" AND policy_eval_needed = 1");
        dataSet.executeQuery();
        if(dataSet.getTotalRowCount() != 1) {
            System.out.println("*WARN* No policy evaluation required for user "+usrKey);
            return;
        }
        
        dataSet.setQuery(dbProvider, "SELECT to_char(sysdate, 'yyyymmddHH24MISS') FROM dual");
        dataSet.executeQuery();
        dataSet.goToRow(0);
        String startTimestamp = dataSet.getString(0);
        
        AccessPolicyServiceInternal accessPolicyServiceInternal = oimClient.getService(AccessPolicyServiceInternal.class);
        ContextManager.pushContext(null, ContextManager.ContextTypes.ADMIN, null);
        ContextManager.setValue("operationInitiator", new ContextAwareString("scheduler"), true);
        accessPolicyServiceInternal.evaluatePoliciesForUser(usrKey);
        ContextManager.popContext();
        
        dataSet.setQuery(dbProvider, "SELECT * FROM user_provisioning_attrs WHERE usr_key = "+usrKey+" AND policy_eval_needed = 0 AND policy_eval_in_progress = 0 AND update_date >= to_timestamp('"+startTimestamp+"', 'yyyymmddHH24MISS')");
        dataSet.executeQuery();
        int waited = 0;
        while (dataSet.getTotalRowCount() == 0) {
            if(waited == maxWaitSeconds) {
                throw new RuntimeException("Maximum waiting time of " + maxWaitSeconds + " seconds reached");
            }
            
            Thread.sleep(1000); // 1 second
            waited++;
            dataSet.refresh();
        }
    }
    
    @RobotKeyword("Returns an all strings dictionary containing the accountid, accountstatus and parent form data of the specified account in OIM.\n\n" +
        "Optional argument _parentformsearchdata_ is a dictionary that specifies name/value pairs of parent form data.\n\n" +
        "For possible _accountstatus_ values, see [http://docs.oracle.com/cd/E40329_01/apirefs.1112/e28159/oracle/iam/provisioning/api/ProvisioningConstants.ObjectStatus.html|ProvisioningConstants.ObjectStatus].\n\n" +
        "Any date typed attributes must be specified and are also returned as _yyyy-MM-dd HH:mm:ss.SSS_, ready to use with [http://robotframework.org/robotframework/latest/libraries/DateTime.html|DateTime].\n\n" +
        "Example:\n" +
        "| ${searchdict}= | [http://robotframework.org/robotframework/latest/libraries/Collections.html#Create%20Dictionary|Create Dictionary] | UD_DUM_USR_USERNAME | DUMMY |\n" +
        "| ${account}= | Get Oim Account | ${usrkey} | DummyApp | accountstatus=Provisioned | parentformsearchdata=${searchdict} |\n" +
        "| ${accountid}= | [http://robotframework.org/robotframework/latest/libraries/Collections.html#Get%20From%20Dictionary|Get From Dictionary] | ${account} | accountid |\n"+
        "| ${accountstatus}= | [http://robotframework.org/robotframework/latest/libraries/Collections.html#Get%20From%20Dictionary|Get From Dictionary] | ${account} | accountstatus |\n"+
        "| Should Be Equal | ${accountstatus} | Provisioned |\n"+
        "See `Get Oim User` how to obtain a ${usrkey}.")
    @ArgumentNames({"usrkey", "appinstname", "accountstatus=", "parentformsearchdata="})
    public HashMap<String, String> getOimAccount(String usrkey, String appinstname, String accountstatus, HashMap<String, String> parentformsearchdata) throws UserNotFoundException,
                                                                                        GenericProvisioningException, ApplicationInstanceNotFoundException, GenericAppInstanceServiceException {
        
        List<Account> accounts = searchAccounts(usrkey, appinstname, accountstatus, parentformsearchdata, true);
        
        if(accounts.size() != 1) {
            throw new RuntimeException("Found "+accounts.size()+" accounts for OIM user "+usrkey+" that match: appinstname="+appinstname+",accountstatus="+accountstatus+",parentformsearchdata="+parentformsearchdata);
        }
        
        Account account = accounts.get(0);
        
        return getOimAccountReturnMap(account);
    }
    
    @RobotKeywordOverload
    public HashMap<String, String> getOimAccount(String usrkey, String appinstname, String accountstatus) throws UserNotFoundException, GenericProvisioningException,
                                                                                                ApplicationInstanceNotFoundException, GenericAppInstanceServiceException {
        return getOimAccount(usrkey, appinstname, accountstatus, null);
    }
    
    @RobotKeywordOverload
    public HashMap<String, String> getOimAccount(String usrkey, String appinstname) throws UserNotFoundException, GenericProvisioningException,
                                                                                ApplicationInstanceNotFoundException, GenericAppInstanceServiceException {
        return getOimAccount(usrkey, appinstname, null, null);
    }
    
    private HashMap<String, String> getOimAccountReturnMap(Account account) {
        HashMap<String, String> returnMap = new HashMap<String, String>();
        returnMap.put("accountid", account.getAccountID());
        returnMap.put("accountstatus", account.getAccountStatus());
        for (Map.Entry<String, Object> entry : account.getAccountData().getData().entrySet()) {
            if(entry.getValue() instanceof Date) {
                Date value = (Date) entry.getValue();
                returnMap.put(entry.getKey(), timestampDateFormat.format(value));
            } else if (entry.getValue() instanceof Timestamp) {
                Timestamp value = (Timestamp) entry.getValue();
                returnMap.put(entry.getKey(), timestampDateFormat.format(new Date(value.getTime())));
            } else if (entry.getValue() != null){
                returnMap.put(entry.getKey(), entry.getValue().toString());
            } else {
                returnMap.put(entry.getKey(), "");
            }
        }
        return returnMap;
    }
    
    @RobotKeyword("Fail if user does not have specified account in OIM. See `Get Oim Account` for more information on usage.")
    @ArgumentNames({"usrkey", "appinstname", "objstatus=", "parentformsearchdata="})
    public void oimAccountShouldExist(String usrkey, String appinstname, String objstatus, HashMap<String, String> parentformsearchdata) throws UserNotFoundException,
                                                                                        GenericProvisioningException, ApplicationInstanceNotFoundException, GenericAppInstanceServiceException {
        
        boolean populateAccountData = true;
        if(parentformsearchdata == null || parentformsearchdata.isEmpty()) {
            populateAccountData = false;
        }
        List<Account> accounts = searchAccounts(usrkey, appinstname, objstatus, parentformsearchdata, populateAccountData);
        
        if(accounts.isEmpty()) {
            throw new RuntimeException("OIM user "+usrkey+" does not have any account that matches: appinstname="+appinstname+",objstatus="+objstatus+",parentformsearchdata="+parentformsearchdata);
        }
    }
    
    @RobotKeywordOverload
    public void oimAccountShouldExist(String usrkey, String appinstname, String objstatus) throws UserNotFoundException,
                                                                                                GenericProvisioningException, ApplicationInstanceNotFoundException,
                                                                                                GenericAppInstanceServiceException {
        oimAccountShouldExist(usrkey, appinstname, objstatus, null);
    }
    
    @RobotKeywordOverload
    public void oimAccountShouldExist(String usrkey, String appinstname) throws UserNotFoundException,
                                                                                GenericProvisioningException, ApplicationInstanceNotFoundException,
                                                                                GenericAppInstanceServiceException {
        oimAccountShouldExist(usrkey, appinstname, null, null);
    }
    
    @RobotKeyword("Fail if user has specified account in OIM. See `Get Oim Account` for more information on usage.")
    @ArgumentNames({"usrkey", "appinstname", "objstatus=", "parentformsearchdata="})
    public void oimAccountShouldNotExist(String usrkey, String appinstname, String objstatus, HashMap<String, String> parentformsearchdata) throws UserNotFoundException,
                                                                                        GenericProvisioningException, ApplicationInstanceNotFoundException, GenericAppInstanceServiceException {
        boolean populateAccountData = true;
        if(parentformsearchdata == null || parentformsearchdata.isEmpty()) {
            populateAccountData = false;
        }
        List<Account> accounts = searchAccounts(usrkey, appinstname, objstatus, parentformsearchdata, populateAccountData);
        
        if(accounts.size() == 1) {
            throw new RuntimeException("OIM user "+usrkey+" has 1 account that matches: appinstname="+appinstname+",objstatus="+objstatus+",parentformsearchdata="+parentformsearchdata);
        } else if(accounts.size() > 1) {
            throw new RuntimeException("OIM user "+usrkey+" has "+accounts.size()+" accounts that match: appinstname="+appinstname+",objstatus="+objstatus+",parentformsearchdata="+parentformsearchdata);
        }
    }
    
    @RobotKeywordOverload
    public void oimAccountShouldNotExist(String usrkey, String appinstname, String objstatus) throws UserNotFoundException,
                                                                                                GenericProvisioningException, ApplicationInstanceNotFoundException,
                                                                                                GenericAppInstanceServiceException {
        oimAccountShouldNotExist(usrkey, appinstname, objstatus, null);
    }
    
    @RobotKeywordOverload
    public void oimAccountShouldNotExist(String usrkey, String appinstname) throws UserNotFoundException,
                                                                                GenericProvisioningException, ApplicationInstanceNotFoundException,
                                                                                GenericAppInstanceServiceException {
        oimAccountShouldNotExist(usrkey, appinstname, null, null);
    }
    
    @RobotKeyword("Returns all role attributes as an all strings dictionary.\n\n" +
                    "Argument _rolesearchattributes_ is a dictionary.\n\n" +
                    "Any date typed attributes must be specified and are also returned as _yyyy-MM-dd HH:mm:ss.SSS_, ready to use with [http://robotframework.org/robotframework/latest/libraries/DateTime.html|DateTime].\n\n" +
                    "Example:\n" +
                    "| ${searchdict}= | [http://robotframework.org/robotframework/latest/libraries/Collections.html#Create%20Dictionary|Create Dictionary] | Role Name | SYSTEM ADMINISTRATORS |\n" +
                    "| ${role}= | Get Oim Role | ${searchdict} |\n" + 
                    "| [http://robotframework.org/robotframework/latest/libraries/BuiltIn.html#Log%20To%20Console|Log To Console] | ${role} |\n" + 
                    "| ${rolekey}= | [http://robotframework.org/robotframework/latest/libraries/Collections.html#Get%20From%20Dictionary|Get From Dictionary] | ${role} | Role Key |")
    @ArgumentNames({"rolesearchattributes"})
    public HashMap<String, String> getOimRole(HashMap<String, String> rolesearchattributes) throws AccessDeniedException, RoleSearchException, ConfigManagerException, NoSuchAttributeException, ParseException  {
        
        List<Role> roles = searchRoles(rolesearchattributes);
       
        if(roles.isEmpty()) {
            throw new RuntimeException("No roles in OIM match '"+rolesearchattributes.toString()+"'");
        } else if(roles.size() > 1) {
            throw new RuntimeException("Multiple roles in OIM match '"+rolesearchattributes.toString()+"'");
        } else {
            Role role = roles.get(0);
            
            HashMap<String, String> returnMap = new HashMap<String, String>();
            for (Map.Entry<String, Object> entry : role.getAttributes().entrySet()) {
                if(entry.getValue() instanceof Date) {
                    Date value = (Date) entry.getValue();
                    returnMap.put(entry.getKey(), timestampDateFormat.format(value));
                } else if (entry.getValue() != null){
                    returnMap.put(entry.getKey(), entry.getValue().toString());
                } else {
                    returnMap.put(entry.getKey(), "");
                }
            }
            
            return returnMap;
        }
    }
    
    @RobotKeyword("Returns all user attributes as an all strings dictionary.\n\n" +
                    "Argument _usersearchattributes_ is a dictionary. For default OIM user attribute names see [http://docs.oracle.com/cd/E40329_01/apirefs.1112/e28159/oracle/iam/identity/usermgmt/api/UserManagerConstants.AttributeName.html|UserManagerConstants.AttributeName].\n\n" +
                    "Any date typed attributes must be specified and are also returned as _yyyy-MM-dd HH:mm:ss.SSS_, ready to use with [http://robotframework.org/robotframework/latest/libraries/DateTime.html|DateTime].\n\n" +
                    "Example:\n" +
                    "| ${startdate}= | [http://robotframework.org/robotframework/latest/libraries/DateTime.html#Convert%20Date|Convert Date] | 2014-05-02 |\n" +
                    "| ${searchdict}= | [http://robotframework.org/robotframework/latest/libraries/Collections.html#Create%20Dictionary|Create Dictionary] | Last Name | dummy | Start Date | ${startdate} |\n" +
                    "| ${user}= | Get Oim User | ${searchdict} |\n" + 
                    "| [http://robotframework.org/robotframework/latest/libraries/BuiltIn.html#Log%20To%20Console|Log To Console] | ${user} |\n" + 
                    "| ${usrkey}= | [http://robotframework.org/robotframework/latest/libraries/Collections.html#Get%20From%20Dictionary|Get From Dictionary] | ${user} | usr_key |")
    @ArgumentNames({"usersearchattributes"})
    public HashMap<String, String> getOimUser(HashMap<String, String> usersearchattributes) throws AccessDeniedException, UserSearchException, NoSuchAttributeException, ConfigManagerException, ParseException {
        
        List<User> users = searchUsers(usersearchattributes);
       
        if(users.isEmpty()) {
            throw new RuntimeException("No users in OIM match '"+usersearchattributes.toString()+"'");
        } else if(users.size() > 1) {
            throw new RuntimeException("Multiple users in OIM match '"+usersearchattributes.toString()+"'");
        } else {
            User user = users.get(0);
            
            HashMap<String, String> returnMap = new HashMap<String, String>();
            for (Map.Entry<String, Object> entry : user.getAttributes().entrySet()) {
                if(entry.getValue() instanceof Date) {
                    Date value = (Date) entry.getValue();
                    returnMap.put(entry.getKey(), timestampDateFormat.format(value));
                } else if (entry.getValue() != null){
                    returnMap.put(entry.getKey(), entry.getValue().toString());
                } else {
                    returnMap.put(entry.getKey(), "");
                }
            }
            
            return returnMap;
        }
    }
    
    @RobotKeyword("Modifies parent form data specified in dictionary _modifyparentformdata_ of account identified by _accountid_. Returns the modified account, same as `Get Oim Account`.\n\n" +
                    "Any date typed attributes must be specified and are also returned as _yyyy-MM-dd HH:mm:ss.SSS_, ready to use with [http://robotframework.org/robotframework/latest/libraries/DateTime.html|DateTime].\n\n" +
                    "See `Get Oim Account` how to obtain an ${accountid}.")
    @ArgumentNames({"accountid","modifyparentformdata"})
    public HashMap<String, String> modifyOimAccount(String accountid, HashMap<String, String> modifyparentformdata) throws AccountNotFoundException, oracle.iam.platform.authopss.exception.AccessDeniedException, GenericProvisioningException, ParseException   {
        
        ProvisioningService provisioningService = oimClient.getService(ProvisioningService.class);
        
        Account account = provisioningService.getAccountDetails(Long.valueOf(accountid));
        
        Map<String, Object> parentFormData = account.getAccountData().getData();
        
        for (Map.Entry<String, String> entry : modifyparentformdata.entrySet()) {
            String key = entry.getKey();
            String newValueStr = entry.getValue();
            
            if(!parentFormData.containsKey(key)) {
                throw new RuntimeException("Parent form data does not contain field '"+key+"'. It contains the following fields: "+parentFormData.keySet());
            }
            
            Object currentValue = parentFormData.get(key);
            Object newValue = null;
            
            if (currentValue instanceof Date) {
                if(!newValueStr.isEmpty()) {
                    newValue = timestampDateFormat.parse(newValueStr);
                }
            } else if (currentValue instanceof Timestamp) {
                if(!newValueStr.isEmpty()) {
                    Date d = timestampDateFormat.parse(newValueStr);
                    newValue = new Timestamp(d.getTime());
                }
            } else {
                newValue = newValueStr;
            }
            
            parentFormData.put(key, newValue);
        }
        
        System.out.println("*INFO* Modifying account "+accountid+" with form data "+modifyparentformdata.toString());
        
        provisioningService.modify(account);
        
        return getOimAccountReturnMap(account);
    }
    
    @RobotKeyword("Modifies attributes specified in dictionary _modifyattributes_ of role identified by _rolekey_. Returns the modified role (including all attributes) as an all strings dictionary.\n\n" +
                    "Any date typed attributes must be specified and are also returned as _yyyy-MM-dd HH:mm:ss.SSS_, ready to use with [http://robotframework.org/robotframework/latest/libraries/DateTime.html|DateTime].\n\n" +
                    "Example:\n" +
                    "| ${moddict}= | [http://robotframework.org/robotframework/latest/libraries/Collections.html#Create%20Dictionary|Create Dictionary] | Role Display Name | Customer Admin |\n" +
                    "| ${role}=  | Modify Oim Role | ${rolekey} | ${moddict} |\n" +
                    "See `Get Oim Role` how to obtain a ${rolekey}.")
    @ArgumentNames({"rolekey","modifyattributes"})
    public HashMap<String, String> modifyOimRole(String rolekey, HashMap<String, String> modifyattributes) throws NoSuchAttributeException, ConfigManagerException, ParseException, ValidationFailedException, AccessDeniedException, RoleModifyException, NoSuchRoleException, RoleSearchException {
        
        Role roleModify = new Role(rolekey);
        
        ConfigManager configManager = oimClient.getService(ConfigManager.class);
        RoleManager roleManager = oimClient.getService(RoleManager.class);
        
        for (Map.Entry<String, String> entry : modifyattributes.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            
            AttributeDefinition attributeDefinition = configManager.getAttribute(Constants.Entity.ROLE, key);
            if (attributeDefinition.getBackendType().equalsIgnoreCase("date")) {
                if(!value.toString().isEmpty()) {
                    value = timestampDateFormat.parse(value.toString());
                }
            } else if (attributeDefinition.getBackendType().equalsIgnoreCase("number")) {
                if(!value.toString().isEmpty()) {
                    value = Long.valueOf(value.toString());
                }
            }
            roleModify.setAttribute(key, value);
        }
        
        System.out.println("*INFO* Modifying role "+rolekey+" with attributes "+roleModify.toString());
        
        roleManager.modify(roleModify);
        
        HashMap<String, String> rolesearchattributes = new HashMap<String, String>();
        rolesearchattributes.put(RoleManagerConstants.RoleAttributeName.KEY.getId(), rolekey);
        return getOimRole(rolesearchattributes);
    }
    
    @RobotKeyword("Modifies attributes specified in dictionary _modifyattributes_ of user identified by _usrkey_. Returns the modified user (including all attributes) as an all strings dictionary.\n\n" +
                    "For default OIM user attribute names see [http://docs.oracle.com/cd/E40329_01/apirefs.1112/e28159/oracle/iam/identity/usermgmt/api/UserManagerConstants.AttributeName.html|UserManagerConstants.AttributeName].\n\n" +
                    "Any date typed attributes must be specified and are also returned as _yyyy-MM-dd HH:mm:ss.SSS_, ready to use with [http://robotframework.org/robotframework/latest/libraries/DateTime.html|DateTime].\n\n" +
                    "Example:\n" +
                    "| ${newstartdate}= | Convert Date | 2014-01-01 |\n" +
                    "| ${moddict}= | [http://robotframework.org/robotframework/latest/libraries/Collections.html#Create%20Dictionary|Create Dictionary] | Start Date | ${newstartdate} |\n" +
                    "| ${user}=  | Modify Oim User | ${usrkey} | ${moddict} |\n" +
                    "| ${startdate}= | Get From Dictionary | ${user} | Start Date |\n" +
                    "| Should Be Equal | ${startdate} | ${newstartdate} |\n"+
                    "See `Get Oim User` how to obtain a ${usrkey}.")
    @ArgumentNames({"usrkey","modifyattributes"})
    public HashMap<String, String> modifyOimUser(String usrkey, HashMap<String, String> modifyattributes) throws AccessDeniedException, UserSearchException, NoSuchAttributeException, ConfigManagerException, ParseException, ValidationFailedException, UserModifyException, NoSuchUserException {
        
        User userModify = new User(usrkey);
        
        ConfigManager configManager = oimClient.getService(ConfigManager.class);
        UserManager userManager = oimClient.getService(UserManager.class);
        
        for (Map.Entry<String, String> entry : modifyattributes.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            
            AttributeDefinition attributeDefinition = configManager.getAttribute(Constants.Entity.USER, key);
            if (attributeDefinition.getBackendType().equalsIgnoreCase("date")) {
                if(!value.toString().isEmpty()) {
                    value = timestampDateFormat.parse(value.toString());
                }
            } else if (attributeDefinition.getBackendType().equalsIgnoreCase("number")) {
                if(!value.toString().isEmpty()) {
                    value = Long.valueOf(value.toString());
                }
            }
            userModify.setAttribute(key, value);
        }
        
        System.out.println("*INFO* Modifying user "+usrkey+" with attributes "+userModify.toString());
        
        userManager.modify(userModify);
        
        HashMap<String, String> usersearchattributes = new HashMap<String, String>();
        usersearchattributes.put(UserManagerConstants.AttributeName.USER_KEY.getId(), usrkey);
        return getOimUser(usersearchattributes);
    }
    
    @RobotKeyword("Fail if user is not present in OIM. See `Get Oim User` for more information on usage.")
    @ArgumentNames({"usersearchattributes"})
    public void oimUserShouldExist(HashMap<String, String> usersearchattributes) throws AccessDeniedException, UserSearchException, NoSuchAttributeException, ConfigManagerException, ParseException {
       
        List<User> users = searchUsers(usersearchattributes);
       
        if(users.isEmpty()) {
            throw new RuntimeException("OIM does not have any user that matches '"+usersearchattributes.toString()+"'");
        }
    }
    
    @RobotKeyword("Fail if user is present in OIM. See `Get Oim User` for more information on usage.")
    @ArgumentNames({"usersearchattributes"})
    public void oimUserShouldNotExist(HashMap<String, String> usersearchattributes) throws AccessDeniedException, UserSearchException, NoSuchAttributeException, ConfigManagerException, ParseException {
       
        List<User> users = searchUsers(usersearchattributes);
       
        if(users.size() > 0) {
            throw new RuntimeException("OIM has one or more users that match '"+usersearchattributes.toString()+"'");
        }
    }
   
    @RobotKeyword("Fail if role is not present in OIM. See `Get Oim Role` for more information on usage.")
    @ArgumentNames({"rolesearchattributes"})
    public void oimRoleShouldExist(HashMap<String, String> rolesearchattributes) throws AccessDeniedException, RoleSearchException, NoSuchAttributeException, ConfigManagerException, ParseException {
       
        List<Role> roles = searchRoles(rolesearchattributes);
       
        if(roles.isEmpty()) {
            throw new RuntimeException("OIM does not have any role that matches '"+rolesearchattributes.toString()+"'");
        }
    }
   
    @RobotKeyword("Fail if role is present in OIM. See `Get Oim Role` for more information on usage.")
    @ArgumentNames({"rolesearchattributes"})
    public void oimRoleShouldNotExist(HashMap<String, String> rolesearchattributes) throws AccessDeniedException, RoleSearchException, NoSuchAttributeException, ConfigManagerException, ParseException {
       
        List<Role> roles = searchRoles(rolesearchattributes);
       
        if(roles.size() > 0) {
            throw new RuntimeException("OIM has one or more roles that match '"+rolesearchattributes.toString()+"'");
        }
    }
   
    @RobotKeyword("Fail if given access policy is not present in OIM.")
    @ArgumentNames({"policyname"})
    public void oimAccessPolicyShouldExist(String policyname) throws tcAPIException, tcAPIException {
       
        tcResultSet policies = searchAccessPolicies(policyname);
       
        if(policies.getRowCount() == 0) {
            throw new RuntimeException("OIM does not have any access policy or policies that match the name '"+policyname+"'");
        }
    }
   
    @RobotKeyword("Fail if given access policy is present in OIM.")
    @ArgumentNames({"policyname"})
    public void oimAccessPolicyShouldNotExist(String policyname) throws tcAPIException, tcAPIException {
       
        tcResultSet policies = searchAccessPolicies(policyname);
       
        if(policies.getRowCount() > 0) {
            throw new RuntimeException("OIM has one or more access policies that match the name '"+policyname+"'");
        }
    }
   
    @RobotKeyword("Run the OIM scheduled job with given jobname.")
    @ArgumentNames({"jobname"})
    public void runOimScheduledJob(String jobname) throws SchedulerException, SchedulerAccessDeniedException,
                                                          InterruptedException, NoJobHistoryFoundException {
        runJob(jobname, false);
    }
   
    @RobotKeyword("Run the OIM scheduled job with given jobname and wait for it to finish.")
    @ArgumentNames({"jobname"})
    public void runOimScheduledJobAndWait(String jobname) throws SchedulerException, SchedulerAccessDeniedException,
                                                          InterruptedException, NoJobHistoryFoundException {
        runJob(jobname, true);
    }
   
    @RobotKeyword("Set a parameter on an OIM scheduled job.")
    @ArgumentNames({"jobname","paramname","paramvalue"})
    public void setOimJobParameter(String jobname, String paramname, String paramvalue) throws SchedulerException, IncorrectScheduleTaskDefinationException, RequiredParameterNotSetException,
                                                                                               ParameterValueTypeNotSupportedException, LastModifyDateNotSetException, SchedulerAccessDeniedException {
        if (oimClient == null) {
            throw new RuntimeException("There is no connection to OIM");
        }
        SchedulerService schedulerService = oimClient.getService(SchedulerService.class);
       
        JobDetails jd = schedulerService.getJobDetail(jobname);
        ScheduledTask taskName = schedulerService.lookupScheduledTask(jd.getTaskName());
       
        HashMap<String, JobParameter> taskParamMap = taskName.getParameters();
        JobParameter jp = taskParamMap.get(paramname);
       
        if(jp == null) {
            throw new RuntimeException("Job "+jobname+" has no parameter named "+paramname);
        }
       
        if(jp.getDataType().equals(JobParameter.DATA_TYPE_STRING)) {
            jp.setValue(paramvalue);
        } else if(jp.getDataType().equals(JobParameter.DATA_TYPE_NUMBER)) {
            jp.setValue(Long.valueOf(paramvalue));
        } else if(jp.getDataType().equals(JobParameter.DATA_TYPE_BOOLEAN)) {
            jp.setValue(Boolean.valueOf(paramvalue));
        } else if(jp.getDataType().equals(JobParameter.DATA_TYPE_ITRESOURCE)) {
            throw new RuntimeException("Data type "+JobParameter.DATA_TYPE_ITRESOURCE+" of parameter "+paramname+" is not implemented.");
        } else {
            throw new RuntimeException("Parameter "+paramname+" has unexpected data type "+jp.getDataType());
        }
       
        HashMap<String, JobParameter> jph = jd.getParams();
        jph.put(paramname, jp);
        jd.setParams(jph);
       
        System.out.println("*INFO* Setting value " + jp.getValue().toString());
       
        schedulerService.updateJob(jd);
    }
    
    @RobotKeyword("Updates one or more entries in the lookup identified by _lookupcode_. All entries having an encode value that matches _encode_ will be updated to have decode value _decode_.\n\n"+
                "Examples:\n"+
                "| `Add Oim Lookup Value` | Lookup.Appl.Config | timeout | 30 | | |\n" +
                "| `Add Oim Lookup Value` | Lookup.Appl.Config | timeout-single | 30 | | |\n" +
                "| `Add Oim Lookup Value` | Lookup.Appl.Config | timeout-double | 30 | | |\n" +
                "| Update Oim Lookup Values | Lookup.Appl.Config | encode=timeout | newdecode=40 | | # change decode value of entry with encode 'timeout' to 40 |\n" +
                "| Update Oim Lookup Values | Lookup.Appl.Config | encode=timeout* | newdecode=60 | | # change decode value of all entries having an encode value starting with 'timeout' to 60 |\n" +
                "| Update Oim Lookup Values | Lookup.Appl.Config | encode=timeout | newdecode=70 | newencode=timeout2 | # change decode value of entry having encode 'timeout' to 70, and also change its encode to 'timeout2' |\n" +
                "| Update Oim Lookup Values | Lookup.Appl.Config | encode=timeout2 | newencode=timeout | | # change encode value back to 'timeout' |\n" +
                "| Update Oim Lookup Values | Lookup.Appl.Config | decode=60 | newdecode=120 | | # change decode value of all entries having decode value 60 to 120 |\n" +
                "| Update Oim Lookup Values | Lookup.Appl.Config | decode=* | newdecode=240 | | # change decode value of all entries to 120 |\n" +
                "| Update Oim Lookup Values | Lookup.Appl.Config | encode=timeout | decode=240 | newdecode=340 | # change decode value of entry having encode 'timeout' and decode '240' to 340 |")
    @ArgumentNames({"lookupcode","encode=","decode=","newencode=","newdecode="})
    public void updateOimLookupValues(String lookupcode, String encode, String decode, String newencode, String newdecode) throws tcAPIException, tcInvalidLookupException, tcColumnNotFoundException, tcInvalidAttributeException, tcInvalidValueException {
        if (oimClient == null) {
            throw new RuntimeException("There is no connection to OIM");
        }
        
        if((encode == null || encode.isEmpty()) && (decode == null || decode.isEmpty())) {
            throw new IllegalArgumentException("Either 'encode' or 'decode' or both must be specified.");
        }
        if((newencode == null || newencode.isEmpty()) && (newdecode == null || newdecode.isEmpty())) {
            throw new IllegalArgumentException("Either 'newencode' or 'newdecode' or both must be specified.");
        }
        
        tcLookupOperationsIntf lookupIntf = oimClient.getService(tcLookupOperationsIntf.class);
        
        Map<String, String> filter = new HashMap<String, String>(2);
        if(encode != null && !encode.isEmpty()) {
            filter.put(LOOKUP_ENCODE_NAME, encode);
        }
        if(decode != null && !decode.isEmpty()) {
            filter.put(LOOKUP_DECODE_NAME, decode);
        }
        tcResultSet resultSet = lookupIntf.getLookupValues(lookupcode, filter);
        
        System.out.println("*INFO* Found " + resultSet.getRowCount() + " entries in lookup " + lookupcode + " that match " + filter);
        
        Map<String, String> updateMap = new HashMap<String, String>(2);
        for(int i=0; i<resultSet.getRowCount(); i++) {
            resultSet.goToRow(i);
            
            String currentEncode = resultSet.getStringValue(LOOKUP_ENCODE_NAME);
            String currentDecode = resultSet.getStringValue(LOOKUP_DECODE_NAME);
            
            if(newencode == null || newencode.isEmpty()) {
                updateMap.put(LOOKUP_ENCODE_NAME, currentEncode);
            } else {
                updateMap.put(LOOKUP_ENCODE_NAME, newencode);
            }
            if(newdecode == null || newdecode.isEmpty()) {
                updateMap.put(LOOKUP_DECODE_NAME, currentDecode);
            } else {
                updateMap.put(LOOKUP_DECODE_NAME, newdecode);
            }
            
            System.out.println("*INFO* Updating encode '"+currentEncode+"' to encode '"+updateMap.get(LOOKUP_ENCODE_NAME)+"' and decode '"+updateMap.get(LOOKUP_DECODE_NAME)+"'");
            
            lookupIntf.updateLookupValue(lookupcode, currentEncode, updateMap);
        }
    }
    
    @RobotKeyword("Set the password of user identified by _usrkey_ to _newpassword_. See `Get Oim User` how to obtain a ${usrkey}.")
    @ArgumentNames({"usrkey","newpassword"})
    public void setOimUserPassword(String usrkey, String newpassword) throws AccessDeniedException, UserManagerException, NoSuchUserException, SearchKeyNotUniqueException {
        
        UserManager userManager = oimClient.getService(UserManager.class);
        userManager.changePassword(UserManagerConstants.AttributeName.USER_KEY.getId(), usrkey, newpassword.toCharArray(), false);
    }
    
    @RobotKeywordOverload
    public void updateOimLookupValues(String lookupcode, String encode, String decode, String newencode) throws tcAPIException, tcInvalidLookupException, tcColumnNotFoundException, tcInvalidAttributeException, tcInvalidValueException {
        updateOimLookupValues(lookupcode, encode, decode, newencode, null);
    }
    
    @RobotKeywordOverload
    public void updateOimLookupValues(String lookupcode, String encode, String decode) throws tcAPIException, tcInvalidLookupException, tcColumnNotFoundException, tcInvalidAttributeException, tcInvalidValueException {
        updateOimLookupValues(lookupcode, encode, decode, null, null);
    }
    
    @RobotKeywordOverload
    public void updateOimLookupValues(String lookupcode, String encode) throws tcAPIException, tcInvalidLookupException, tcColumnNotFoundException, tcInvalidAttributeException, tcInvalidValueException {
        updateOimLookupValues(lookupcode, encode, null, null, null);
    }
    
    @RobotKeyword("Returns the encode and decode value of the entry identified by _encode_ and/or _decode_ from the lookup identified by _lookupcode_. A single entry should match.\n\n"+
                "The return value is a dictionary with two keys: 'encode' and 'decode'.\n\n"+
                "Example:\n"+
                "| ${lookupvalue}= | Get Oim Lookup Value | Lookup.Appl.Config | encode=timeout |\n" +
                "| ${encode}= | Get From Dictionary | ${lookupvalue} | encode |\n" +
                "| ${decode}= | Get From Dictionary | ${lookupvalue} | decode |")
    @ArgumentNames({"lookupcode","encode=","decode="})
    public HashMap<String, String> getOimLookupValue(String lookupcode, String encode, String decode) throws tcAPIException, tcInvalidLookupException, tcColumnNotFoundException {
        if (oimClient == null) {
            throw new RuntimeException("There is no connection to OIM");
        }
        
        if((encode == null || encode.isEmpty()) && (decode == null || decode.isEmpty())) {
            throw new IllegalArgumentException("Either 'encode' or 'decode' or both must be specified.");
        }
        
        tcLookupOperationsIntf lookupIntf = oimClient.getService(tcLookupOperationsIntf.class);
        
        Map<String, String> filter = new HashMap<String, String>(2);
        if(encode != null && !encode.isEmpty()) {
            filter.put(LOOKUP_ENCODE_NAME, encode);
        }
        if(decode != null && !decode.isEmpty()) {
            filter.put(LOOKUP_DECODE_NAME, decode);
        }
        tcResultSet resultSet = lookupIntf.getLookupValues(lookupcode, filter);
        
        System.out.println("*INFO* Found " + resultSet.getRowCount() + " entries in lookup " + lookupcode + " that match " + filter);
        
        if(resultSet.isEmpty()) {
            throw new RuntimeException("No entry in OIM lookup '"+lookupcode+"' matches "+filter);
        } else if(resultSet.getRowCount() > 1) {
            throw new RuntimeException("Multiple entries in OIM lookup '"+lookupcode+"' match "+filter);
        } else {
            resultSet.goToRow(0);
            HashMap<String, String> returnMap = new HashMap<String, String>(2);
            returnMap.put("encode", resultSet.getStringValue(LOOKUP_ENCODE_NAME));
            returnMap.put("decode", resultSet.getStringValue(LOOKUP_DECODE_NAME));
            return returnMap;
        }
    }
    
    @RobotKeywordOverload
    public HashMap<String, String> getOimLookupValue(String lookupcode, String encode) throws tcAPIException, tcInvalidLookupException, tcColumnNotFoundException {
        return getOimLookupValue(lookupcode, encode, null);
    }
   
    @RobotKeyword("Get a parameter value of an OIM scheduled job.")
    @ArgumentNames({"jobname","paramname"})
    public String getOimJobParameter(String jobname, String paramname) throws SchedulerException {
        if (oimClient == null) {
            throw new RuntimeException("There is no connection to OIM");
        }
        SchedulerService schedulerService = oimClient.getService(SchedulerService.class);
       
        JobDetails jd = schedulerService.getJobDetail(jobname);
        JobParameter jp = jd.getParams().get(paramname);
       
        if(jp == null) {
            throw new RuntimeException("Job "+jobname+" has no parameter named "+paramname);
        }
       
        System.out.println("*INFO* Returning value " + jp.getValue().toString());
       
        return jp.getValue().toString();
    }
    
    @RobotKeyword("Removes one or more entries from lookup identified by _lookupcode_. All entries matching _encode_ and _decode_ are removed.\n\n"+
                "Examples:\n" +
                "| Delete Oim Lookup Values | Lookup.Appl.Config | encode=timeout | | # Remove entry having encode 'timeout' from lookup |\n" +
                "| Delete Oim Lookup Values | Lookup.Appl.Config | decode=240 | | # Remove all entries having decode value 240 |\n" +
                "| Delete Oim Lookup Values | Lookup.Appl.Config | encode=timeout* | | # Remove all entries having encode value that starts with 'timeout' |\n" +
                "| Delete Oim Lookup Values | Lookup.Appl.Config | encode=timeout | decode=30 | # Remove entry having encode 'timeout' and decode value 30 from lookup |")
    @ArgumentNames({"lookupcode","encode=","decode="})
    public void deleteOimLookupValues(String lookupcode, String encode, String decode) throws tcAPIException, tcInvalidLookupException, tcColumnNotFoundException, tcInvalidValueException {
        if (oimClient == null) {
            throw new RuntimeException("There is no connection to OIM");
        }
        
        if((encode == null || encode.isEmpty()) && (decode == null || decode.isEmpty())) {
            throw new IllegalArgumentException("Either 'encode' or 'decode' or both must be specified.");
        }
        
        tcLookupOperationsIntf lookupIntf = oimClient.getService(tcLookupOperationsIntf.class);
        
        Map<String, String> filter = new HashMap<String, String>(2);
        if(encode != null && !encode.isEmpty()) {
            filter.put(LOOKUP_ENCODE_NAME, encode);
        }
        if(decode != null && !decode.isEmpty()) {
            filter.put(LOOKUP_DECODE_NAME, decode);
        }
        tcResultSet resultSet = lookupIntf.getLookupValues(lookupcode, filter);
        
        System.out.println("*INFO* Found " + resultSet.getRowCount() + " entries in lookup " + lookupcode + " that match " + filter);
        
        for(int i=0; i<resultSet.getRowCount(); i++) {
            resultSet.goToRow(i);
            
            String currentEncode = resultSet.getStringValue(LOOKUP_ENCODE_NAME);
            String currentDecode = resultSet.getStringValue(LOOKUP_DECODE_NAME);
            
            System.out.println("*INFO* Removing encode '"+currentEncode+"' having decode '"+currentDecode+"'");
            
            lookupIntf.removeLookupValue(lookupcode, currentEncode);
        }
    }
    
    @RobotKeywordOverload
    public void deleteOimLookupValues(String lookupcode, String encode) throws tcAPIException, tcInvalidLookupException, tcColumnNotFoundException, tcInvalidValueException {
        deleteOimLookupValues(lookupcode, encode, null);
    }
   
    @SuppressWarnings("SleepWhileInLoop")
    private void runJob(String jobname, boolean wait) throws SchedulerException, SchedulerAccessDeniedException,
                                                             InterruptedException, NoJobHistoryFoundException {
        if (oimClient == null) {
            throw new RuntimeException("There is no connection to OIM.");
        }
        SchedulerService schedulerService = oimClient.getService(SchedulerService.class);
       
        if(schedulerService.getJobDetail(jobname) == null) {
            throw new RuntimeException("No job found with name '" + jobname + "'");
        }
       
        int jobStatus = schedulerService.getStatusOfJob(jobname);
       
        if(jobStatus != JobStatus.STOPPED.ordinal() && jobStatus != JobStatus.RUNNING.ordinal()) {
            throw new RuntimeException("Job '" + jobname + "' is not in STOPPED or RUNNING state");
        } else if(jobStatus == JobStatus.RUNNING.ordinal()) {
            System.out.println("*INFO* Job '" + jobname + "' is already in RUNNING state");
        } else {
            schedulerService.triggerNow(jobname);
           
            System.out.println("*INFO* Job '" + jobname + "' has been triggered");
        }
       
        if(wait) {
            do {
                Thread.sleep(10000); // 10 seconds
                jobStatus = schedulerService.getStatusOfJob(jobname);
            } while (jobStatus == JobStatus.RUNNING.ordinal());
           
            System.out.println("*INFO* Job '" + jobname + "' is no longer in RUNNING state");
           
            JobHistory jobHistory = schedulerService.getLastHistoryOfJob(jobname);
            int jobHistoryStatus = Integer.valueOf(jobHistory.getStatus());
           
            String level;
            if(jobStatus != JobStatus.STOPPED.ordinal() || jobHistoryStatus != JobStatus.STOPPED.ordinal()) {
                level = "*WARN*";
            } else {
                level = "*INFO*";
            }
           
            System.out.println(level + " Job '" + jobname + "' has finished with status " + JobStatus.values()[jobStatus] + " and history status " + JobStatus.values()[jobHistoryStatus]);
        }
    }
    
    private EntitlementInstance searchEntitlementInstance(String accountid, String childform, String entitlement) throws AccountNotFoundException,
                                                                    GenericProvisioningException, UserNotFoundException {
        if (oimClient == null) {
            throw new RuntimeException("There is no connection to OIM");
        }
        ProvisioningService provisioningService = oimClient.getService(ProvisioningService.class);
        
        Account account = provisioningService.getAccountDetails(Long.valueOf(accountid));
        
        List<EntitlementInstance> entitlementInstances = provisioningService.getEntitlementsForUser(account.getUserKey());
        
        Long accountKey = Long.valueOf(accountid);
        for(EntitlementInstance instance : entitlementInstances) {
            
            if (accountKey == instance.getAccountKey() &&
                childform.equalsIgnoreCase(instance.getEntitlement().getFormName()) &&
                entitlement.equalsIgnoreCase(instance.getEntitlement().getEntitlementValue()))
            {
                return instance;
            }
        }
        return null;
    }
    
    private List<Account> searchAccounts(String usrkey, String appinstname, String accountstatus, HashMap<String, String> parentformsearchdata, boolean populateAccountData) throws UserNotFoundException,
                                                                                        GenericProvisioningException, ApplicationInstanceNotFoundException, GenericAppInstanceServiceException {
        if (oimClient == null) {
            throw new RuntimeException("There is no connection to OIM");
        }
        ProvisioningService provisioningService = oimClient.getService(ProvisioningService.class);
        
        ApplicationInstanceService applicationInstanceService = oimClient.getService(ApplicationInstanceService.class);
        
        ApplicationInstance appInst = applicationInstanceService.findApplicationInstanceByName(appinstname);
        
        SearchCriteria criteria = new SearchCriteria(ProvisioningConstants.AccountSearchAttribute.APPINST_KEY.getId(), appInst.getApplicationInstanceKey(), SearchCriteria.Operator.EQUAL);
        if(accountstatus != null && !accountstatus.isEmpty()) {
            criteria = new SearchCriteria(criteria, new SearchCriteria(ProvisioningConstants.AccountSearchAttribute.ACCOUNT_STATUS.getId(), accountstatus, SearchCriteria.Operator.EQUAL), SearchCriteria.Operator.AND);
        }
        
        System.out.println("*INFO* Searching for accounts for user with key "+usrkey+" matching: criteria="+criteria.toString());
        
        List<Account> accounts = provisioningService.getAccountsProvisionedToUser(usrkey, criteria, null, populateAccountData);
        
        System.out.println("*TRACE* Found "+accounts.size()+" accounts");
        
        if(parentformsearchdata != null && accounts.size() > 0) {
            
            Iterator<Account> i = accounts.iterator();
            while(i.hasNext()) {
                Account account = i.next();
                
                System.out.println("*TRACE* Handling account "+account.getAccountID());
                
                Map<String, Object> parentFormData = account.getAccountData().getData();
                
                for (Map.Entry<String, String> searchEntry : parentformsearchdata.entrySet()) {
                    String searchKey = searchEntry.getKey();
                    String searchValue = searchEntry.getValue();
                    
                    Object formValue = parentFormData.get(searchKey);
                    
                    String strFormValue;
                    
                    if(formValue == null) {
                        strFormValue = "";
                    } else if (formValue instanceof Date) {
                        strFormValue = timestampDateFormat.format(formValue);
                    } else if (formValue instanceof Timestamp) {
                        Timestamp t = (Timestamp) formValue;
                        strFormValue = timestampDateFormat.format(new Date(t.getTime()));
                    } else {
                        strFormValue = formValue.toString();
                    }
                    
                    if (!strFormValue.equals(searchValue)) {
                        System.out.println("*TRACE* Excluding account "+account.getAccountID()+" because '"+strFormValue+"' not equal to '"+searchValue+"'");
                        i.remove();
                        break;
                    }
                }
            }
        }
        
        return accounts;
    }
    
    private List<User> searchUsers (HashMap<String, String> usersearchattributes) throws AccessDeniedException, UserSearchException, NoSuchAttributeException, ConfigManagerException, ParseException {
        if (oimClient == null) {
            throw new RuntimeException("There is no connection to OIM");
        }
        
        ConfigManager configManager = oimClient.getService(ConfigManager.class);
        UserManager userManager = oimClient.getService(UserManager.class);
        
        SearchCriteria searchCriteria = null;
        for (Map.Entry<String, String> entry : usersearchattributes.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            
            AttributeDefinition attributeDefinition = configManager.getAttribute(Constants.Entity.USER, key);
            if (attributeDefinition.getBackendType().equalsIgnoreCase("date")) {
                value = timestampDateFormat.parse(value.toString());
            } else if (attributeDefinition.getBackendType().equalsIgnoreCase("number")) {
                value = Long.valueOf(value.toString());
            }
            
            if(searchCriteria == null) {
                searchCriteria = new SearchCriteria(key, value, SearchCriteria.Operator.EQUAL);
            } else {
                searchCriteria = new SearchCriteria(searchCriteria, new SearchCriteria(key, value, SearchCriteria.Operator.EQUAL), SearchCriteria.Operator.AND);
            }
        }
        
        System.out.println("*INFO* Searching for users matching '"+searchCriteria+"'");
        
        List<User> users = userManager.search(searchCriteria, null, null);
        
        System.out.println("*TRACE* Found "+users.size()+" users");
        
        return users;
    }
    
    private List<Role> searchRoles (HashMap<String, String> rolesearchattributes) throws AccessDeniedException, RoleSearchException, NoSuchAttributeException, ConfigManagerException, ParseException {
        if (oimClient == null) {
            throw new RuntimeException("There is no connection to OIM");
        }
        
        ConfigManager configManager = oimClient.getService(ConfigManager.class);
        RoleManager roleManager = oimClient.getService(RoleManager.class);
        
        SearchCriteria searchCriteria = null;
        for (Map.Entry<String, String> entry : rolesearchattributes.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            
            AttributeDefinition attributeDefinition = configManager.getAttribute(Constants.Entity.ROLE, key);
            if (attributeDefinition.getBackendType().equalsIgnoreCase("date")) {
                value = timestampDateFormat.parse(value.toString());
            } else if (attributeDefinition.getBackendType().equalsIgnoreCase("number")) {
                value = Long.valueOf(value.toString());
            }
            
            if(searchCriteria == null) {
                searchCriteria = new SearchCriteria(key, value, SearchCriteria.Operator.EQUAL);
            } else {
                searchCriteria = new SearchCriteria(searchCriteria, new SearchCriteria(key, value, SearchCriteria.Operator.EQUAL), SearchCriteria.Operator.AND);
            }
        }
        
        System.out.println("*INFO* Searching for roles matching '"+searchCriteria+"'");
       
        List<Role> roles = roleManager.search(searchCriteria, null, null);
       
        return roles;
    }
   
    private tcResultSet searchAccessPolicies (String policyname) throws tcAPIException, tcAPIException {
        if (oimClient == null) {
            throw new RuntimeException("There is no connection to OIM");
        }
        tcAccessPolicyOperationsIntf polIntf = oimClient.getService(tcAccessPolicyOperationsIntf.class);
       
        Map<String,String> hm = new HashMap<String,String>();
        hm.put("Access Policies.Name", policyname);
       
        System.out.println("*INFO* Searching for access policy having name '"+policyname+"'");
       
        tcResultSet ts = polIntf.findAccessPolicies(hm);
       
        return ts;
    }
}
