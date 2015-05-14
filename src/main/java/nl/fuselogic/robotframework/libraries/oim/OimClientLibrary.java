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
import Thor.API.Operations.tcAccessPolicyOperationsIntf;
import Thor.API.tcResultSet;

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
import oracle.iam.configservice.api.ConfigManager;
import oracle.iam.configservice.api.Constants;
import oracle.iam.configservice.exception.ConfigManagerException;
import oracle.iam.configservice.exception.NoSuchAttributeException;
import oracle.iam.configservice.vo.AttributeDefinition;
import oracle.iam.identity.exception.NoSuchUserException;

import oracle.iam.identity.exception.RoleSearchException;
import oracle.iam.identity.exception.UserDeleteException;
import oracle.iam.identity.exception.UserDisableException;
import oracle.iam.identity.exception.UserLookupException;
import oracle.iam.identity.exception.UserModifyException;
import oracle.iam.identity.exception.UserSearchException;
import oracle.iam.identity.exception.ValidationFailedException;
import oracle.iam.identity.rolemgmt.api.RoleManager;
import oracle.iam.identity.rolemgmt.api.RoleManagerConstants.RoleAttributeName;
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
   
    private OIMClient oimClient;
    
    private static SimpleDateFormat timestampDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
   
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
   
    @RobotKeyword("Make a connection to OIM")
    @ArgumentNames({"username", "password", "url"})
    public synchronized void connectToOim(String username, String password, String url) throws LoginException {
        
        if(oimClient != null) {
            try {
                // Check if connection is still valid by getting user details
                AuthenticatedSelfService authenticatedSelfService = oimClient.getService(AuthenticatedSelfService.class);
                Set<String> retAttrs = new HashSet<String>();
                retAttrs.add(UserManagerConstants.AttributeName.USER_LOGIN.getId());
                User user = authenticatedSelfService.getProfileDetails(retAttrs);
                
                if(user.getLogin().equalsIgnoreCase(username)) {
                    System.out.println("*WARN* There is already a connection to OIM");
                    return;
                } else {
                    System.out.println("*WARN* There is already a connection to OIM as user "+user.getLogin()+". Going to reconnect as user "+username+".");
                }
            } catch (Exception e) {
                System.out.println("*TRACE* Got exception "+e.getClass().getName()+ ". Message: " +e.getMessage());
                System.out.println("*WARN* There is already a connection to OIM, but it might be stale. Going to reconnect.");
            }
        }
        
        System.out.println("*INFO* Connecting to "+url+" as "+username);
       
        Hashtable env = new Hashtable();
        env.put(OIMClient.JAVA_NAMING_FACTORY_INITIAL, OIMClient.WLS_CONTEXT_FACTORY);
        env.put(OIMClient.JAVA_NAMING_PROVIDER_URL, url);
       
        oimClient = new OIMClient(env);
        oimClient.login(username, password.toCharArray());
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
   
    @RobotKeyword("Fail if given rolename is not present in OIM.")
    @ArgumentNames({"rolename"})
    public void oimRoleShouldExist(String rolename) throws AccessDeniedException, RoleSearchException {
       
        List<Role> roles = searchRoles(rolename);
       
        if(roles.isEmpty()) {
            throw new RuntimeException("OIM does not have any role or roles that match the name '"+rolename+"'");
        }
    }
   
    @RobotKeyword("Fail if given rolename is present in OIM.")
    @ArgumentNames({"rolename"})
    public void oimRoleShouldNotExist(String rolename) throws AccessDeniedException, RoleSearchException {
       
        List<Role> roles = searchRoles(rolename);
       
        if(roles.size() > 0) {
            throw new RuntimeException("OIM has one or more roles that match the name '"+rolename+"'");
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
                    
                    String strFormValue = null;
                    
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
    
    private List<Role> searchRoles (String rolename) throws AccessDeniedException, RoleSearchException {
        if (oimClient == null) {
            throw new RuntimeException("There is no connection to OIM");
        }
        RoleManager roleManager = oimClient.getService(RoleManager.class);
       
        Set<String> retAttrs = new HashSet<String>();
        retAttrs.add(RoleAttributeName.KEY.getId());
        retAttrs.add(RoleAttributeName.NAME.getId());
       
        System.out.println("*INFO* Searching for role having name '"+rolename+"'");
       
        List<Role> roles = roleManager.search(
                            new SearchCriteria(RoleAttributeName.NAME.getId(), rolename, SearchCriteria.Operator.EQUAL),
                            retAttrs,
                            null);
       
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
