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


import Thor.API.Exceptions.*;
import Thor.API.Operations.tcAccessPolicyOperationsIntf;
import Thor.API.Operations.tcLookupOperationsIntf;
import Thor.API.Operations.tcProvisioningOperationsIntf;
import Thor.API.Security.XLClientSecurityAssociation;
import Thor.API.tcResultSet;
import com.thortech.xl.dataaccess.tcClientDataAccessException;
import com.thortech.xl.dataaccess.tcDataBaseClient;
import com.thortech.xl.dataaccess.tcDataProvider;
import com.thortech.xl.dataaccess.tcDataSetException;
import com.thortech.xl.dataobj.tcDataSet;
import com.thortech.xl.orb.dataaccess.tcDataAccessException;
import oracle.iam.accesspolicy.api.AccessPolicyServiceInternal;
import oracle.iam.accesspolicy.exception.AccessPolicyEvaluationException;
import oracle.iam.accesspolicy.exception.AccessPolicyEvaluationUnauthorizedException;
import oracle.iam.accesspolicy.exception.AccessPolicyServiceException;
import oracle.iam.accesspolicy.exception.UserNotActiveException;
import oracle.iam.conf.api.SystemConfigurationService;
import oracle.iam.conf.exception.SystemConfigurationServiceException;
import oracle.iam.conf.vo.SystemProperty;
import oracle.iam.configservice.api.ConfigManager;
import oracle.iam.configservice.api.Constants;
import oracle.iam.configservice.exception.ConfigManagerException;
import oracle.iam.configservice.exception.NoSuchAttributeException;
import oracle.iam.configservice.vo.AttributeDefinition;
import oracle.iam.identity.exception.*;
import oracle.iam.identity.orgmgmt.api.OrganizationManager;
import oracle.iam.identity.orgmgmt.api.OrganizationManagerConstants;
import oracle.iam.identity.orgmgmt.vo.Organization;
import oracle.iam.identity.rolemgmt.api.RoleManager;
import oracle.iam.identity.rolemgmt.api.RoleManagerConstants;
import oracle.iam.identity.rolemgmt.vo.Role;
import oracle.iam.identity.usermgmt.api.UserManager;
import oracle.iam.identity.usermgmt.api.UserManagerConstants;
import oracle.iam.identity.usermgmt.vo.User;
import oracle.iam.identity.usermgmt.vo.UserManagerResult;
import oracle.iam.platform.OIMClient;
import oracle.iam.platform.authz.exception.AccessDeniedException;
import oracle.iam.platform.context.ContextAwareString;
import oracle.iam.platform.context.ContextManager;
import oracle.iam.platform.entitymgr.vo.SearchCriteria;
import oracle.iam.provisioning.api.ApplicationInstanceService;
import oracle.iam.provisioning.api.ProvisioningConstants;
import oracle.iam.provisioning.api.ProvisioningService;
import oracle.iam.provisioning.exception.*;
import oracle.iam.provisioning.vo.Account;
import oracle.iam.provisioning.vo.ApplicationInstance;
import oracle.iam.provisioning.vo.ChildTableRecord;
import oracle.iam.provisioning.vo.EntitlementInstance;
import oracle.iam.scheduler.api.SchedulerService;
import oracle.iam.scheduler.exception.*;
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

import javax.security.auth.login.LoginException;
import java.io.InputStream;
import java.sql.Timestamp;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


@RobotKeywords
public class OimClientLibrary extends AnnotationLibrary {

    @SuppressWarnings("unused")
    public static final String ROBOT_LIBRARY_VERSION = "0.3";

    @SuppressWarnings("unused")
    private enum JobStatus { SHUTDOWN, STARTED, STOPPED, NONE, PAUSED, RUNNING, FAILED, INTERRUPT }

    @SuppressWarnings("unused")
    private enum ProcessStatus { WAITING,  ABANDONED,  COMPLETED,  MANUAL_COMPLETED,  ACTIVE,  FAILED,  CANCELLED,  PENDING_CANCELLED,  PENDING_CANCELLED_WITH_COMPENSATION,  CANCELLED_WITH_COMPENSATION,  COMPENSATED,  RESTARTED }
   
    private OIMClient oimClient;
    private String oimUrl;
    
    private static SimpleDateFormat timestampDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
    
    private static String LOOKUP_ENCODE_NAME= "Lookup Definition.Lookup Code Information.Code Key";
    private static String LOOKUP_DECODE_NAME= "Lookup Definition.Lookup Code Information.Decode";
    
    private static int maxWaitSeconds = 300;
    
    private static Pattern itResourcePrefixPattern = Pattern.compile("^(\\d+~)");
   
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
                    Set<String> retAttrs = new HashSet<>();
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

        Hashtable<String, String> env = new Hashtable<>();
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
    
    @RobotKeyword("Fails if specified account does not have specified child form entries.\n\n" +
                "Argument _multiplesearchcriteria_ must be a list of dictionaries, where each dictionary must match exactly one unique child form entry. Also see `Oim Account Should Have Child Form Entry`.\n\n" + 
                "The total number of entries in the child form must be equal to the number of dictionaries provided in list _multiplesearchcriteria_.\n\n" +
                "Any internal OIM prefix consisting of one ore more digits followed by a tilde (~) is discarded during value comparisons.\n\n" +
                "Example:\n" +
                "| ${searchdict}= | [http://robotframework.org/robotframework/latest/libraries/Collections.html#Create%20Dictionary|Create Dictionary] | UD_DUM_ENT_ENTNAME=Write |\n" +
                "| ${searchdict2}= | [http://robotframework.org/robotframework/latest/libraries/Collections.html#Create%20Dictionary|Create Dictionary] | UD_DUM_ENT_ENTNAME=Read |\n" +
                "| ${multiplesearchcriteria}= | [http://robotframework.org/robotframework/latest/libraries/BuiltIn.html#Create%20List|Create List] | ${searchdict} | ${searchdict2} |\n" +
                "| Oim Account Should Have Child Form Entries | ${accountid} | UD_DUM_ENT |  ${multiplesearchcriteria} |\n" +
                "See `Get Oim Account` how to obtain an ${accountid}.")
    @ArgumentNames({"accountid","childform","multiplesearchcriteria"})
    public void oimAccountShouldHaveChildFormEntries(String accountid, String childform, List<Map<String, String>> multiplesearchcriteria) throws AccountNotFoundException, oracle.iam.platform.authopss.exception.AccessDeniedException, GenericProvisioningException {
        if (oimClient == null) {
            throw new RuntimeException("There is no connection to OIM");
        }
        
        ProvisioningService provisioningService = oimClient.getService(ProvisioningService.class);
        
        Map<String, Object> account = getOimAccountReturnMap(provisioningService.getAccountDetails(Long.valueOf(accountid)));

        @SuppressWarnings("unchecked")
        List<Map<String, String>> childFormList = (List<Map<String, String>>)account.get(childform);
        
        if(childFormList == null) {
            throw new RuntimeException("Child form not found: accountid="+accountid+", childform="+childform);
        }
        
        List<Map<String, String>> allChildFormRows = searchChildFormEntries(childFormList, new HashMap<String, String>());
        
        List<Map<String, String>> searchcriteriaNotFound = new ArrayList<>();
        Set<Map<String, String>> allMatchingRows = new HashSet<>();
        for (Map<String, String> singleSearchcriteria : multiplesearchcriteria) {
            
            List<Map<String, String>> matchingRows = searchChildFormEntries(childFormList, singleSearchcriteria);
            
            if(matchingRows.size() > 1) {
                throw new RuntimeException("Expected at most 1 child form entry to match, instead found "+matchingRows.size()+": accountid="+accountid+", childform="+childform+", searchcriteria="+singleSearchcriteria);
            }
            
            if(matchingRows.isEmpty()) {
                searchcriteriaNotFound.add(singleSearchcriteria);
            } else {
                allMatchingRows.add(matchingRows.get(0));
            }
        }
        
        allChildFormRows.removeAll(allMatchingRows);
        List<Map<String, String>> additionalEntries = allChildFormRows;

        String errorMessage = "";
        
        if(multiplesearchcriteria.size() != allMatchingRows.size()) {
            errorMessage += "\n\nExpected "+multiplesearchcriteria.size()+" entries to match, but instead matched "+allMatchingRows.size()+": " + allMatchingRows;
        }

        if(!additionalEntries.isEmpty()) {
            errorMessage += "\n\nFound "+additionalEntries.size()+" additional non-matched entries: " + additionalEntries;
        }

        if(!searchcriteriaNotFound.isEmpty()) {
            errorMessage += "\n\nNo entries were matched for: " + searchcriteriaNotFound;
        }
        
        if(!errorMessage.isEmpty()) {
            errorMessage =
                    "Child form entries not exactly matched: accountid="+accountid+", childform="+childform+", multiplesearchcriteria="+multiplesearchcriteria + errorMessage;
            throw new RuntimeException(errorMessage);
        }
    }
    
    @RobotKeyword("Fails if specified account does not have specified child form entry.\n\n"+
                    "Optional _searchcriteria_ can contain multiple entries, to match multi-field child forms.\n\n" +
                    "Any internal OIM prefix consisting of one ore more digits followed by a tilde (~) is discarded during value comparisons.\n\n" +
                    "Example:\n" +
                    "| ${searchdict}= | [http://robotframework.org/robotframework/latest/libraries/Collections.html#Create%20Dictionary|Create Dictionary] | UD_DUM_ENT_ENTNAME=Write |\n" +
                    "| Oim Account Should Have Child Form Entry | ${accountid} | UD_DUM_ENT | ${searchdict} |\n" +
                    "See `Get Oim Account` how to obtain an ${accountid}.\n\n" +
                    "To check a complete child form, see `Oim Account Should Have Child Form Entries`")
    @ArgumentNames({"accountid","childform","searchcriteria="})
    public void oimAccountShouldHaveChildFormEntry(String accountid, String childform, Map<String, String> searchcriteria) throws AccountNotFoundException, oracle.iam.platform.authopss.exception.AccessDeniedException, GenericProvisioningException {
        
        List<Map<String, String>> allMatchingRows = searchChildForm(accountid, childform, searchcriteria);
        
        if(allMatchingRows.size() != 1 && !searchcriteria.isEmpty()) {
            throw new RuntimeException("Expected 1 child form entry to match, instead found "+allMatchingRows.size()+": accountid="+accountid+", childform="+childform+", searchcriteria="+searchcriteria);
        }
    }
    
    @RobotKeywordOverload
    public void oimAccountShouldHaveChildFormEntry(String accountid, String childform) throws AccountNotFoundException, oracle.iam.platform.authopss.exception.AccessDeniedException, GenericProvisioningException {
        oimAccountShouldHaveChildFormEntry(accountid, childform, new HashMap<String, String>());
    }
    
    @RobotKeyword("Fails if specified account has specified child form entry. See `Oim Account Should Have Child Form Entry` for more information on usage.")
    @ArgumentNames({"accountid","childform","searchcriteria="})
    public void oimAccountShouldNotHaveChildFormEntry(String accountid, String childform, Map<String, String> searchcriteria) throws AccountNotFoundException, oracle.iam.platform.authopss.exception.AccessDeniedException, GenericProvisioningException {
        
        List<Map<String, String>> allMatchingRows = searchChildForm(accountid, childform, searchcriteria);
        
        if(allMatchingRows.size() > 0) {
            throw new RuntimeException("Expected 0 child form entries to match, instead found "+allMatchingRows.size()+": accountid="+accountid+", childform="+childform+", searchcriteria="+searchcriteria);
        }
    }
    
    @RobotKeywordOverload
    public void oimAccountShouldNotHaveChildFormEntry(String accountid, String childform) throws AccountNotFoundException, oracle.iam.platform.authopss.exception.AccessDeniedException, GenericProvisioningException {
        oimAccountShouldNotHaveChildFormEntry(accountid, childform, new HashMap<String, String>());
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

    @RobotKeyword(  "Creates a user in OIM and returns the ${usrkey} of the new user. Use `Get Oim User` for the list of available attributes.\n\n"+
                    "Argument _userattributes_ is a dictionary. For default OIM user attribute names see [http://docs.oracle.com/cd/E40329_01/apirefs.1112/e28159/oracle/iam/identity/usermgmt/api/UserManagerConstants.AttributeName.html|UserManagerConstants.AttributeName].\n\n" +
                    "Any date typed attributes must be specified as _yyyy-MM-dd HH:mm:ss.SSS_, ready to use with [http://robotframework.org/robotframework/latest/libraries/DateTime.html|DateTime].\n\n")
    @ArgumentNames({"userAttributes"})
    public String createOimUser(Map<String, String> userAttributes) throws UserAlreadyExistsException, ValidationFailedException, UserCreateException, OrganizationManagerException, ConfigManagerException, ParseException {
        if (userAttributes == null) {
            throw new RuntimeException("No attributes are passed. Attributes should be passed to specify the new user.");
        }

        if (oimClient == null) {
            throw new RuntimeException("There is no connection to OIM");
        }

        ConfigManager configManager = oimClient.getService(ConfigManager.class);

        // move all entries to a hashmap. Since the User constructor needs a hashmap. And we got a map.
        // also parse the date and number fields
        HashMap<String, Object> userData = new HashMap<>();
        for (Map.Entry<String, String> entry : userAttributes.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();

            AttributeDefinition attributeDefinition = configManager.getAttribute(Constants.Entity.USER, key);
            if (attributeDefinition.getBackendType().equalsIgnoreCase("date")){
                if (!value.toString().isEmpty()){
                    value = timestampDateFormat.parse(value.toString());
                }
            }else if (attributeDefinition.getBackendType().equalsIgnoreCase("number")) {
                if(!value.toString().isEmpty()) {
                    value = Long.valueOf(value.toString());
                }
            }
            userData.put(key, value);
        }
        if (userData.containsKey(UserManagerConstants.AttributeName.USER_LOGIN.getId())){
            System.out.println("*INFO* Creating user (" + userData.get(UserManagerConstants.AttributeName.USER_LOGIN.getId()) + ") with attributes " + userData.toString());
        } else{
            System.out.println("*INFO* Creating user with attributes " + userData.toString());
        }

        // get the login for the user, or null when it should be generated
        String login = (String) userData.get(UserManagerConstants.AttributeName.USER_LOGIN.getId());

        // set the organization
        if (userData.containsKey(OrganizationManagerConstants.AttributeName.ORG_NAME.getId())){
            // the user specified the organization name instead of the organization key. Going to get the organization key
            String organizationName = (String) userData.get(OrganizationManagerConstants.AttributeName.ORG_NAME.getId());

            OrganizationManager organizationManager = oimClient.getService(OrganizationManager.class);

            Organization organization = organizationManager.getDetails(organizationName, null, true);
            String actKey = organization.getEntityId();
            userData.put(OrganizationManagerConstants.AttributeName.ID_FIELD.getId(), actKey);
        }

        UserManager userManager = oimClient.getService(UserManager.class);
        User user = new User(login, userData);

        UserManagerResult result = userManager.create(user);
        return result.getEntityId();
    }
    
    @RobotKeyword(  "Deletes specified user in OIM.\n\n"+
                    "Set _force_ to True if immediate deletion is required, even if OIM system property _XL.UserDeleteDelayPeriod_ is set to a non-zero value. If mentioned system property is set to zero,  _force_  has no effect: the deletion will always be immediate.\n\n"+
                    "See `Get Oim User` how to obtain a ${usrkey}.")
    @ArgumentNames({"usrkey","force="})
    public void deleteOimUser(String usrkey, boolean force) throws ValidationFailedException, AccessDeniedException, UserModifyException, NoSuchUserException, UserDeleteException, UserDisableException, UserLookupException, tcDataSetException, InterruptedException, tcAPIException, tcColumnNotFoundException, tcTaskNotFoundException, tcBulkException, SystemConfigurationServiceException, tcDataAccessException, tcClientDataAccessException {
        if (oimClient == null) {
            throw new RuntimeException("There is no connection to OIM");
        }

        UserManager userManager = oimClient.getService(UserManager.class);
        tcProvisioningOperationsIntf provisioningOperationsIntf = oimClient.getService(tcProvisioningOperationsIntf.class);
        SystemConfigurationService systemConfigurationService = oimClient.getService(SystemConfigurationService.class);

        try {
            User user = userManager.getDetails(usrkey, null, false);

            if(!force && user.getAutomaticallyDeleteDate() != null && user.getStatus().equals(UserManagerConstants.AttributeValues.USER_STATUS_DISABLED.getId())) {
                System.out.println("*WARN* User " + usrkey + "(" + getUserLogin(usrkey) + ") is already in delayed delete state. Specify force argument as true to force immediate deletion of user.");
                return;
            } else if (user.getStatus().equals(UserManagerConstants.AttributeValues.USER_STATUS_DELETED.getId())) {
                System.out.println("*WARN* User " + usrkey + "(" + getUserLogin(usrkey) + ") is already deleted");
                return;
            }

            System.out.println("*INFO* Deleting user " + usrkey + "(" + getUserLogin(usrkey) + ")");

            int delayPeriod = 0;
            SystemProperty userDeleteDelayPeriod = systemConfigurationService.getSystemProperty("XL.UserDeleteDelayPeriod");
            if(userDeleteDelayPeriod != null) {
                delayPeriod = Integer.valueOf(userDeleteDelayPeriod.getPtyValue());
            }

            Calendar cal;

            if (force && delayPeriod > 0) {

                System.out.println("*INFO* Bypassing OIM configured delayed delete of "+delayPeriod+" days");

                cal = Calendar.getInstance();
                cal.set(Calendar.HOUR_OF_DAY, 0);
                cal.set(Calendar.MINUTE, 0);
                cal.set(Calendar.SECOND, 0);
                cal.set(Calendar.MILLISECOND, 0);
                Date today = cal.getTime();

                if (user.getAutomaticallyDeleteDate() == null ||
                        user.getAutomaticallyDeleteDate().after(today) ||
                        !user.getStatus().equals(UserManagerConstants.AttributeValues.USER_STATUS_DISABLED.getId())) {
                    tcDataProvider dbProvider = null;
                    try {
                        dbProvider = new tcDataBaseClient();
                        dbProvider.writeStatement("UPDATE usr SET usr_status = '" +
                                UserManagerConstants.AttributeValues.USER_STATUS_DISABLED.getId() +
                                "', usr_disabled = " +
                                UserManagerConstants.AttributeValues.USER_DISABLED.getId() +
                                ", usr_automatically_delete_on = trunc(sysdate) WHERE usr_key = "+user.getEntityId());
                    } finally {
                        try {
                            if (dbProvider != null) {
                                dbProvider.close();
                            }
                        } catch (Exception e) { assert true; }
                    }
                }

                // UserManager API delete operation will only execute a delayed delete
                // if context parameter "operationinitiator" is set to "scheduler".
                ContextManager.pushContext(null, ContextManager.ContextTypes.ADMIN, null);
                ContextManager.setValue("operationinitiator", new ContextAwareString("scheduler"), true);
            }

            cal = Calendar.getInstance();
            cal.add(Calendar.SECOND, -10);
            Date start = cal.getTime();
            userManager.delete(usrkey, false);
            cal = Calendar.getInstance();
            cal.add(Calendar.SECOND, 10);
            Date end = cal.getTime();
            waitForOimOrchestrationsToComplete(usrkey, "User", null, OimClientLibrary.timestampDateFormat.format(start), OimClientLibrary.timestampDateFormat.format(end));

            if (force) {
                ContextManager.popContext();
            }

            Map<String, String> attList = new HashMap<>();
            attList.put("Process Instance.Descriptive Data", user.getLogin());
            tcResultSet provTasksResults = provisioningOperationsIntf.findAllOpenProvisioningTasks(attList, new String[]{});

            if (provTasksResults.getRowCount() > 0) {
                for (int i = 0; i < provTasksResults.getRowCount(); i++) {
                    provTasksResults.goToRow(i);

                    long taskKey = provTasksResults.getLongValue("Process Instance.Task Details.Key");
                    String taskName = provTasksResults.getStringValue("Process Definition.Tasks.Task Name");
                    String objectName = provTasksResults.getStringValue("Objects.Name");

                    System.out.println("*INFO* Going to perform MC action for task " + taskName + " of object " + objectName);
                    try {
                        provisioningOperationsIntf.setTasksCompletedManually(new long[]{taskKey});
                    } catch (Exception e) {
                        System.out.println("*WARN* Exception during manual complete action for task " + taskName + " of object " + objectName + ": " + e.getMessage());
                    }
                }
            }
        }  finally {
            provisioningOperationsIntf.close();
        }
    }
    
    @RobotKeywordOverload
    public void deleteOimUser(String usrkey) throws ValidationFailedException, AccessDeniedException, UserModifyException, NoSuchUserException, UserDeleteException, UserDisableException, UserLookupException, tcDataSetException, InterruptedException, tcAPIException, tcColumnNotFoundException, tcTaskNotFoundException, tcBulkException, SystemConfigurationServiceException, tcDataAccessException, tcClientDataAccessException {
        deleteOimUser(usrkey, false);
    }
    
    @RobotKeyword("Returns true if specified role is present in OIM, false otherwise. See `Get Oim Role` for more information on usage.")
    @ArgumentNames({"rolesearchattributes"})
    public boolean doesOimRoleExist(Map<String, String> rolesearchattributes) throws AccessDeniedException, RoleSearchException, NoSuchAttributeException, ConfigManagerException, ParseException {
       
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
    public boolean doesOimUserExist(Map<String, String> usersearchattributes) throws AccessDeniedException, UserSearchException, NoSuchAttributeException, ConfigManagerException, ParseException {
       
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
        "See `Get Oim User` how to obtain a ${usrkey}.")
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
        int maxInitialWaitSeconds = 30;
        while (dataSet.getTotalRowCount() == 0) {
            if(waited == maxInitialWaitSeconds) {
                System.out.println("*WARN* No matching orchestration processes found within " + maxInitialWaitSeconds + " seconds, continuing");
                return;
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
        waited = 0;
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

    @RobotKeywordOverload
    public void evaluateOimAccessPoliciesForUser(String usrKey) throws NoSuchUserException, UserNotActiveException, AccessPolicyEvaluationUnauthorizedException, AccessPolicyServiceException, AccessPolicyEvaluationException, tcDataSetException, InterruptedException, tcDataAccessException, tcClientDataAccessException, UserLookupException {
        evaluateOimAccessPoliciesForUser(usrKey, false);
    }
    
    @RobotKeyword("Evaluates the access policies for the user specified by _usrkey_. Set optional argument _force_ to _True_ to force a policy evaluation, even if it is not necessary.\n\n" +
        "This keyword returns when the evaluation process in OIM has completed.\n\n" +
        "See `Get Oim User` how to obtain _usrkey_.")
    @ArgumentNames({"usrkey", "force="})
    public void evaluateOimAccessPoliciesForUser(String usrKey, boolean force) throws NoSuchUserException, UserNotActiveException, AccessPolicyEvaluationUnauthorizedException, AccessPolicyServiceException, AccessPolicyEvaluationException, tcDataSetException, InterruptedException, tcDataAccessException, tcClientDataAccessException, UserLookupException {
        if (oimClient == null) {
            throw new RuntimeException("There is no connection to OIM");
        }

        tcDataProvider dbProvider = null;
        try {
            dbProvider = new tcDataBaseClient();
            tcDataSet dataSet = new tcDataSet();

            dataSet.setQuery(dbProvider, "SELECT * FROM user_provisioning_attrs WHERE usr_key = " + usrKey + " AND policy_eval_needed = 1");
            dataSet.executeQuery();
            if (!force && dataSet.getTotalRowCount() != 1) {
                System.out.println("*WARN* Not performing policy evaluation for user " + usrKey + "(" + getUserLogin(usrKey) + ") because it is not necessary");
                return;
            } else if (force && dataSet.getTotalRowCount() != 1) {
                System.out.println("*INFO* Going to force unnecessary policy evaluation for user " + usrKey + "(" + getUserLogin(usrKey) + ")");

                dbProvider.writeStatement("UPDATE user_provisioning_attrs SET policy_eval_needed = 1 WHERE usr_key = " + usrKey);
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

            dataSet.setQuery(dbProvider, "SELECT * FROM user_provisioning_attrs WHERE usr_key = " + usrKey + " AND policy_eval_needed = 0 AND policy_eval_in_progress = 0 AND update_date >= to_timestamp('" + startTimestamp + "', 'yyyymmddHH24MISS')");
            dataSet.executeQuery();
            int waited = 0;
            while (dataSet.getTotalRowCount() == 0) {
                if (waited == maxWaitSeconds) {
                    throw new RuntimeException("Maximum waiting time of " + maxWaitSeconds + " seconds reached");
                }

                Thread.sleep(1000); // 1 second
                waited++;
                dataSet.refresh();
            }
        } finally {
            try {
                if (dbProvider != null) {
                    dbProvider.close();
                }
            } catch (Exception e) { assert true; }
        }
    }
    
    @RobotKeyword("Returns a dictionary containing the accountid, accountstatus, parent form data and child form data of the specified account in OIM.\n\n" +
        "Optional argument _parentformsearchdata_ is a dictionary that specifies name/value pairs of parent form data.\n\n" +
        "For possible _accountstatus_ values, see [http://docs.oracle.com/cd/E40329_01/apirefs.1112/e28159/oracle/iam/provisioning/api/ProvisioningConstants.ObjectStatus.html|ProvisioningConstants.ObjectStatus].\n\n" +
        "Any date typed attributes must be specified and are also returned as _yyyy-MM-dd HH:mm:ss.SSS_, ready to use with [http://robotframework.org/robotframework/latest/libraries/DateTime.html|DateTime].\n\n" +
        "Any internal OIM prefix consisting of one ore more digits followed by a tilde (~) is discarded during value comparisons and is removed from the returned dictionary.\n\n" +
        "Example:\n" +
        "| ${searchdict}= | [http://robotframework.org/robotframework/latest/libraries/Collections.html#Create%20Dictionary|Create Dictionary] | UD_DUM_USR_USERNAME | DUMMY |\n" +
        "| ${account}= | Get Oim Account | ${usrkey} | DummyApp | accountstatus=Provisioned | parentformsearchdata=${searchdict} |\n" +
        "| ${accountid}= | [http://robotframework.org/robotframework/latest/libraries/Collections.html#Get%20From%20Dictionary|Get From Dictionary] | ${account} | accountid |\n"+
        "| ${accountstatus}= | [http://robotframework.org/robotframework/latest/libraries/Collections.html#Get%20From%20Dictionary|Get From Dictionary] | ${account} | accountstatus |\n"+
        "| Should Be Equal | ${accountstatus} | Provisioned |\n"+
        "See `Get Oim User` how to obtain a ${usrkey}.")
    @ArgumentNames({"usrkey", "appinstname", "accountstatus=", "parentformsearchdata="})
    public Map<String, Object> getOimAccount(String usrkey, String appinstname, String accountstatus, Map<String, String> parentformsearchdata) throws UserNotFoundException,
            GenericProvisioningException, ApplicationInstanceNotFoundException, GenericAppInstanceServiceException, UserLookupException, NoSuchUserException {

        List<Account> accounts = searchAccounts(usrkey, appinstname, accountstatus, parentformsearchdata, true);
        
        if(accounts.size() != 1) {
            throw new RuntimeException("Found "+accounts.size()+" accounts for OIM user "+usrkey + "(" + getUserLogin(usrkey) + ") that match: appinstname="+appinstname+",accountstatus="+accountstatus+",parentformsearchdata="+parentformsearchdata);
        }
        
        Account account = accounts.get(0);
        
        return getOimAccountReturnMap(account);
    }
    
    @RobotKeywordOverload
    public Map<String, Object> getOimAccount(String usrkey, String appinstname, String accountstatus) throws UserNotFoundException, GenericProvisioningException,
            ApplicationInstanceNotFoundException, GenericAppInstanceServiceException, UserLookupException, NoSuchUserException {
        return getOimAccount(usrkey, appinstname, accountstatus, null);
    }
    
    @RobotKeywordOverload
    public Map<String, Object> getOimAccount(String usrkey, String appinstname) throws UserNotFoundException, GenericProvisioningException,
            ApplicationInstanceNotFoundException, GenericAppInstanceServiceException, UserLookupException, NoSuchUserException {
        return getOimAccount(usrkey, appinstname, null, null);
    }
    
    private Map<String, Object> getOimAccountReturnMap(Account account) {
        Map<String, Object> returnMap = new HashMap<>();
        returnMap.put("accountid", account.getAccountID());
        returnMap.put("accountstatus", account.getAccountStatus());
        if(account.getAccountData() != null) {
            for (Map.Entry<String, Object> entry : account.getAccountData().getData().entrySet()) {
                
                String strFormValue = OimClientLibrary.getFormStringValue(entry.getValue());
                returnMap.put(entry.getKey(), strFormValue);
            }
            
            if(account.getAccountData().getChildData() != null) {
                for (Map.Entry<String, ArrayList<ChildTableRecord>> entry : account.getAccountData().getChildData().entrySet()) {
                    
                    List<Map<String, String>> childTableEntries = new ArrayList<>();
                    for (ChildTableRecord childTableRecord : account.getAccountData().getChildData().get(entry.getKey())) {
                        
                        Map<String, String> childTableEntry = new HashMap<>();
                        for (Map.Entry<String, Object> childEntry : childTableRecord.getChildData().entrySet()) {
                            
                            String strFormValue = OimClientLibrary.getFormStringValue(childEntry.getValue());
                            childTableEntry.put(childEntry.getKey(), strFormValue);
                        }
                        childTableEntries.add(childTableEntry);
                    }
                    returnMap.put(entry.getKey(), childTableEntries);
                }
            }
        }
        return returnMap;
    }
    
    @RobotKeyword("Fail if user does not have specified account in OIM. See `Get Oim Account` for more information on usage.")
    @ArgumentNames({"usrkey", "appinstname", "objstatus=", "parentformsearchdata="})
    public void oimAccountShouldExist(String usrkey, String appinstname, String objstatus, Map<String, String> parentformsearchdata) throws UserNotFoundException,
            GenericProvisioningException, ApplicationInstanceNotFoundException, GenericAppInstanceServiceException, UserLookupException, NoSuchUserException {
        
        boolean populateAccountData = true;
        if(parentformsearchdata == null || parentformsearchdata.isEmpty()) {
            populateAccountData = false;
        }
        List<Account> accounts = searchAccounts(usrkey, appinstname, objstatus, parentformsearchdata, populateAccountData);
        
        if(accounts.isEmpty()) {
            throw new RuntimeException("OIM user "+usrkey + "(" + getUserLogin(usrkey) + ") does not have any account that matches: appinstname="+appinstname+",objstatus="+objstatus+",parentformsearchdata="+parentformsearchdata);
        }
    }
    
    @RobotKeywordOverload
    public void oimAccountShouldExist(String usrkey, String appinstname, String objstatus) throws UserNotFoundException,
            GenericProvisioningException, ApplicationInstanceNotFoundException,
            GenericAppInstanceServiceException, UserLookupException, NoSuchUserException {
        oimAccountShouldExist(usrkey, appinstname, objstatus, null);
    }
    
    @RobotKeywordOverload
    public void oimAccountShouldExist(String usrkey, String appinstname) throws UserNotFoundException,
            GenericProvisioningException, ApplicationInstanceNotFoundException,
            GenericAppInstanceServiceException, UserLookupException, NoSuchUserException {
        oimAccountShouldExist(usrkey, appinstname, null, null);
    }
    
    @RobotKeyword("Fail if user has specified account in OIM. See `Get Oim Account` for more information on usage.")
    @ArgumentNames({"usrkey", "appinstname", "objstatus=", "parentformsearchdata="})
    public void oimAccountShouldNotExist(String usrkey, String appinstname, String objstatus, Map<String, String> parentformsearchdata) throws UserNotFoundException,
            GenericProvisioningException, ApplicationInstanceNotFoundException, GenericAppInstanceServiceException, UserLookupException, NoSuchUserException {
        boolean populateAccountData = true;
        if(parentformsearchdata == null || parentformsearchdata.isEmpty()) {
            populateAccountData = false;
        }
        List<Account> accounts = searchAccounts(usrkey, appinstname, objstatus, parentformsearchdata, populateAccountData);
        
        if(accounts.size() == 1) {
            throw new RuntimeException("OIM user "+usrkey+" ("+getUserLogin(usrkey)+") has 1 account that matches: appinstname="+appinstname+",objstatus="+objstatus+",parentformsearchdata="+parentformsearchdata);
        } else if(accounts.size() > 1) {
            throw new RuntimeException("OIM user "+usrkey+" ("+getUserLogin(usrkey)+") has "+accounts.size()+" accounts that match: appinstname="+appinstname+",objstatus="+objstatus+",parentformsearchdata="+parentformsearchdata);
        }
    }
    
    @RobotKeywordOverload
    public void oimAccountShouldNotExist(String usrkey, String appinstname, String objstatus) throws UserNotFoundException,
            GenericProvisioningException, ApplicationInstanceNotFoundException,
            GenericAppInstanceServiceException, UserLookupException, NoSuchUserException {
        oimAccountShouldNotExist(usrkey, appinstname, objstatus, null);
    }
    
    @RobotKeywordOverload
    public void oimAccountShouldNotExist(String usrkey, String appinstname) throws UserNotFoundException,
            GenericProvisioningException, ApplicationInstanceNotFoundException,
            GenericAppInstanceServiceException, UserLookupException, NoSuchUserException {
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
    public Map<String, String> getOimRole(Map<String, String> rolesearchattributes) throws AccessDeniedException, RoleSearchException, ConfigManagerException, NoSuchAttributeException, ParseException  {
        
        List<Role> roles = searchRoles(rolesearchattributes);
       
        if(roles.isEmpty()) {
            throw new RuntimeException("No roles in OIM match '"+rolesearchattributes.toString()+"'");
        } else if(roles.size() > 1) {
            throw new RuntimeException("Multiple roles in OIM match '"+rolesearchattributes.toString()+"'");
        } else {
            Role role = roles.get(0);
            
            Map<String, String> returnMap = new HashMap<>();
            for (Map.Entry<String, Object> entry : role.getAttributes().entrySet()) {
                
                String strFormValue = OimClientLibrary.getFormStringValue(entry.getValue());
                returnMap.put(entry.getKey(), strFormValue);
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
    public Map<String, String> getOimUser(Map<String, String> usersearchattributes) throws AccessDeniedException, UserSearchException, NoSuchAttributeException, ConfigManagerException, ParseException {
        
        List<User> users = searchUsers(usersearchattributes);
       
        if(users.isEmpty()) {
            throw new RuntimeException("No users in OIM match '"+usersearchattributes.toString()+"'");
        } else if(users.size() > 1) {
            throw new RuntimeException("Multiple users in OIM match '"+usersearchattributes.toString()+"'");
        } else {
            User user = users.get(0);
            
            Map<String, String> returnMap = new HashMap<>();
            for (Map.Entry<String, Object> entry : user.getAttributes().entrySet()) {
                
                String strFormValue = OimClientLibrary.getFormStringValue(entry.getValue());
                returnMap.put(entry.getKey(), strFormValue);
            }
            
            return returnMap;
        }
    }
    
    @RobotKeyword("Modifies parent form data specified in dictionary _modifyparentformdata_ of account identified by _accountid_. Returns the modified account, same as `Get Oim Account`.\n\n" +
                    "Any date typed attributes must be specified and are also returned as _yyyy-MM-dd HH:mm:ss.SSS_, ready to use with [http://robotframework.org/robotframework/latest/libraries/DateTime.html|DateTime].\n\n" +
                    "See `Get Oim Account` how to obtain an ${accountid}.")
    @ArgumentNames({"accountid","modifyparentformdata"})
    public Map<String, Object> modifyOimAccount(String accountid, Map<String, String> modifyparentformdata) throws AccountNotFoundException, oracle.iam.platform.authopss.exception.AccessDeniedException, GenericProvisioningException, ParseException   {
        
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
            
            if (currentValue instanceof Timestamp) {
                if(!newValueStr.isEmpty()) {
                    Date d = timestampDateFormat.parse(newValueStr);
                    newValue = new Timestamp(d.getTime());
                }
            } else if (currentValue instanceof Date) {
                if(!newValueStr.isEmpty()) {
                    newValue = timestampDateFormat.parse(newValueStr);
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
    public Map<String, String> modifyOimRole(String rolekey, Map<String, String> modifyattributes) throws NoSuchAttributeException, ConfigManagerException, ParseException, ValidationFailedException, AccessDeniedException, RoleModifyException, NoSuchRoleException, RoleSearchException {
        
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
        
        Map<String, String> rolesearchattributes = new HashMap<>();
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
    public Map<String, String> modifyOimUser(String usrkey, Map<String, String> modifyattributes) throws AccessDeniedException, UserSearchException, NoSuchAttributeException, ConfigManagerException, ParseException, ValidationFailedException, UserModifyException, NoSuchUserException, UserLookupException {
        
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

        System.out.println("*INFO* Modifying user "+usrkey+" ("+getUserLogin(usrkey)+") with attributes "+userModify.toString());
        
        userManager.modify(userModify);
        
        Map<String, String> usersearchattributes = new HashMap<>();
        usersearchattributes.put(UserManagerConstants.AttributeName.USER_KEY.getId(), usrkey);
        return getOimUser(usersearchattributes);
    }
    
    @RobotKeyword("Fail if user is not present in OIM. See `Get Oim User` for more information on usage.")
    @ArgumentNames({"usersearchattributes"})
    public void oimUserShouldExist(Map<String, String> usersearchattributes) throws AccessDeniedException, UserSearchException, NoSuchAttributeException, ConfigManagerException, ParseException {
       
        List<User> users = searchUsers(usersearchattributes);
       
        if(users.isEmpty()) {
            throw new RuntimeException("OIM does not have any user that matches '"+usersearchattributes.toString()+"'");
        }
    }
    
    @RobotKeyword("Fail if user is present in OIM. See `Get Oim User` for more information on usage.")
    @ArgumentNames({"usersearchattributes"})
    public void oimUserShouldNotExist(Map<String, String> usersearchattributes) throws AccessDeniedException, UserSearchException, NoSuchAttributeException, ConfigManagerException, ParseException {
       
        List<User> users = searchUsers(usersearchattributes);
       
        if(users.size() > 0) {
            throw new RuntimeException("OIM has one or more users that match '"+usersearchattributes.toString()+"'");
        }
    }
   
    @RobotKeyword("Fail if role is not present in OIM. See `Get Oim Role` for more information on usage.")
    @ArgumentNames({"rolesearchattributes"})
    public void oimRoleShouldExist(Map<String, String> rolesearchattributes) throws AccessDeniedException, RoleSearchException, NoSuchAttributeException, ConfigManagerException, ParseException {
       
        List<Role> roles = searchRoles(rolesearchattributes);
       
        if(roles.isEmpty()) {
            throw new RuntimeException("OIM does not have any role that matches '"+rolesearchattributes.toString()+"'");
        }
    }
   
    @RobotKeyword("Fail if role is present in OIM. See `Get Oim Role` for more information on usage.")
    @ArgumentNames({"rolesearchattributes"})
    public void oimRoleShouldNotExist(Map<String, String> rolesearchattributes) throws AccessDeniedException, RoleSearchException, NoSuchAttributeException, ConfigManagerException, ParseException {
       
        List<Role> roles = searchRoles(rolesearchattributes);
       
        if(roles.size() > 0) {
            throw new RuntimeException("OIM has one or more roles that match '"+rolesearchattributes.toString()+"'");
        }
    }
   
    @RobotKeyword("Fail if given access policy is not present in OIM.")
    @ArgumentNames({"policyname"})
    public void oimAccessPolicyShouldExist(String policyname) throws tcAPIException {
       
        tcResultSet policies = searchAccessPolicies(policyname);
       
        if(policies.getRowCount() == 0) {
            throw new RuntimeException("OIM does not have any access policy or policies that match the name '"+policyname+"'");
        }
    }
   
    @RobotKeyword("Fail if given access policy is present in OIM.")
    @ArgumentNames({"policyname"})
    public void oimAccessPolicyShouldNotExist(String policyname) throws tcAPIException {
       
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
       
        Map<String, JobParameter> taskParamMap = taskName.getParameters();
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
        
        Map<String, String> filter = new HashMap<>(2);
        if(encode != null && !encode.isEmpty()) {
            filter.put(LOOKUP_ENCODE_NAME, encode);
        }
        if(decode != null && !decode.isEmpty()) {
            filter.put(LOOKUP_DECODE_NAME, decode);
        }
        tcResultSet resultSet = lookupIntf.getLookupValues(lookupcode, filter);
        
        System.out.println("*INFO* Found " + resultSet.getRowCount() + " entries in lookup " + lookupcode + " that match " + filter);
        
        Map<String, String> updateMap = new HashMap<>(2);
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
    public void setOimUserPassword(String usrkey, String newpassword) throws AccessDeniedException, UserManagerException, SearchKeyNotUniqueException {
        
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
    public Map<String, String> getOimLookupValue(String lookupcode, String encode, String decode) throws tcAPIException, tcInvalidLookupException, tcColumnNotFoundException {
        if (oimClient == null) {
            throw new RuntimeException("There is no connection to OIM");
        }
        
        if((encode == null || encode.isEmpty()) && (decode == null || decode.isEmpty())) {
            throw new IllegalArgumentException("Either 'encode' or 'decode' or both must be specified.");
        }
        
        tcLookupOperationsIntf lookupIntf = oimClient.getService(tcLookupOperationsIntf.class);
        
        Map<String, String> filter = new HashMap<>(2);
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
            Map<String, String> returnMap = new HashMap<>(2);
            returnMap.put("encode", resultSet.getStringValue(LOOKUP_ENCODE_NAME));
            returnMap.put("decode", resultSet.getStringValue(LOOKUP_DECODE_NAME));
            return returnMap;
        }
    }
    
    @RobotKeywordOverload
    public Map<String, String> getOimLookupValue(String lookupcode, String encode) throws tcAPIException, tcInvalidLookupException, tcColumnNotFoundException {
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
        
        Map<String, String> filter = new HashMap<>(2);
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

        if(jobStatus != JobStatus.STOPPED.ordinal()) {
            throw new RuntimeException("Job '" + jobname + "' is not in STOPPED state");
        }

        long triggerTimestamp = System.currentTimeMillis();
        // Allow for 10 seconds time difference between test system and OIM server
        triggerTimestamp = triggerTimestamp - 10000L;

        System.out.println("*INFO* Triggering job " + jobname);

        schedulerService.triggerNow(jobname);
        if (wait) {
            System.out.println("*INFO* Waiting for job " + jobname + " to finish...");

            final List<Object> statusObject = Arrays.asList(new Object[] {JobStatus.NONE.ordinal(), triggerTimestamp, null, null});
            Runnable statusRunnable = new Runnable() {
                public void run() {
                    System.out.println("*TRACE* Current job status is " + JobStatus.values()[(int) statusObject.get(0)] + ", triggerTimestamp=" + statusObject.get(1) + ", startTime=" + statusObject.get(2) + ", endTime=" + statusObject.get(3));
                }
            };

            ScheduledExecutorService executor = Executors.newScheduledThreadPool(1);
            JobHistory jh = null;
            long startTime = 0L;
            long endTime = 0L;
            try {
                executor.scheduleAtFixedRate(statusRunnable, 30, 30, TimeUnit.SECONDS);

                do {
                    Thread.sleep(1000);
                    List<JobHistory> jhl = schedulerService.getHistoryOfJob(jobname);
                    if(jhl.size() > 0) {
                        jh = jhl.get(0);

                        startTime = jh.getJobStartTime().getTime();
                        endTime = (jh.getJobEndTime() != null) ? jh.getJobEndTime().getTime() : 0;

                        jobStatus = schedulerService.getStatusOfJob(jobname);

                        statusObject.set(0, jobStatus);
                        statusObject.set(2, startTime);
                        statusObject.set(3, endTime);
                    }
                } while (!(startTime >= triggerTimestamp && endTime >= startTime));
            } finally {
                executor.shutdownNow();
            }

            System.out.println("*INFO* Job " + jobname + " is no longer running, current status is " + JobStatus.values()[jobStatus]);

            long runTime = endTime - startTime;
            String elapsed =
                    String.format("Elapsed: %d min, %d sec, %d ms", TimeUnit.MILLISECONDS.toMinutes(runTime), TimeUnit.MILLISECONDS.toSeconds(runTime) - TimeUnit.MINUTES.toSeconds(TimeUnit.MILLISECONDS.toMinutes(runTime)),
                            runTime - TimeUnit.SECONDS.toMillis(TimeUnit.MILLISECONDS.toSeconds(runTime)));
            System.out.println("*INFO* " + elapsed);

            int jobhistStatus = (jh != null) ? Integer.valueOf(jh.getStatus()):JobStatus.NONE.ordinal();

            if (jobStatus != JobStatus.STOPPED.ordinal() || jobhistStatus != JobStatus.STOPPED.ordinal()) {
                System.out.println("*WARN* Job " + jobname + " has finished with status " + JobStatus.values()[jobStatus] + " and history status " + JobStatus.values()[jobhistStatus] + ".");
            }
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
    
    private List<Account> searchAccounts(String usrkey, String appinstname, String accountstatus, Map<String, String> parentformsearchdata, boolean populateAccountData) throws UserNotFoundException,
            GenericProvisioningException, ApplicationInstanceNotFoundException, GenericAppInstanceServiceException, UserLookupException, NoSuchUserException {
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
        
        System.out.println("*INFO* Searching for accounts for user " + usrkey + "(" + getUserLogin(usrkey) + ") matching: criteria="+criteria.toString());
        
        List<Account> accounts = provisioningService.getAccountsProvisionedToUser(usrkey, criteria, null, populateAccountData);
        
        System.out.println("*TRACE* Found "+accounts.size()+" accounts");
        
        if(parentformsearchdata != null && accounts.size() > 0) {
            
            Iterator<Account> i = accounts.iterator();
            while(i.hasNext()) {
                Account account = i.next();
                
                System.out.println("*TRACE* Handling account "+account.getAccountID());
                
                if(account.getAccountData() == null) {
                    System.out.println("*TRACE* Excluding account "+account.getAccountID()+" because it has no form data");
                    i.remove();
                    continue;
                }
                
                Map<String, Object> parentFormData = account.getAccountData().getData();
                
                for (Map.Entry<String, String> searchEntry : parentformsearchdata.entrySet()) {
                    String searchKey = searchEntry.getKey();
                    String searchValue = searchEntry.getValue();
                    
                    Object formValue = parentFormData.get(searchKey);
                    
                    String strFormValue = OimClientLibrary.getFormStringValue(formValue);
                    
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
    
    // Returns all rows in specified childform that match specified searchcriteria
    private List<Map<String, String>> searchChildForm(String accountid, String childform, Map<String, String> searchcriteria) throws AccountNotFoundException, oracle.iam.platform.authopss.exception.AccessDeniedException, GenericProvisioningException {
        if (oimClient == null) {
            throw new RuntimeException("There is no connection to OIM");
        }
        
        ProvisioningService provisioningService = oimClient.getService(ProvisioningService.class);
        
        Map<String, Object> account = getOimAccountReturnMap(provisioningService.getAccountDetails(Long.valueOf(accountid)));
        
        return searchChildForm(account, childform, searchcriteria);
    }
    
    // Returns all rows in specified childform that match specified searchcriteria
    private List<Map<String, String>> searchChildForm(Map<String, Object> account, String childform, Map<String, String> searchcriteria) {

        @SuppressWarnings("unchecked")
        List<Map<String, String>> childFormList = (List<Map<String, String>>)account.get(childform);
        
        if(childFormList == null) {
            throw new RuntimeException("Child form not found: accountid="+account.get("accountid")+", childform="+childform);
        }
        
        return searchChildFormEntries(childFormList, searchcriteria);
    }
    
    // Returns all rows in specified childform that match specified searchcriteria
    private List<Map<String, String>> searchChildFormEntries(List<Map<String, String>> childFormList, Map<String, String> searchcriteria) {
        
        List<Map<String, String>> allMatchingRows = new ArrayList<>();
        
        for (Map<String, String> childFormRow : childFormList) {
            boolean matchingRow = true;
            
            for (Map.Entry<String, String> selectionEntry : searchcriteria.entrySet()) {
                String searchKey = selectionEntry.getKey();
                String searchValue = selectionEntry.getValue();
                
                Object formValue = childFormRow.get(searchKey);

                String strFormValue = OimClientLibrary.getFormStringValue(formValue);
                
                if (!strFormValue.equals(searchValue)) {
                    matchingRow = false;
                    break;
                }
            }
            
            if(matchingRow) {
                allMatchingRows.add(childFormRow);
            }
        }
        return allMatchingRows;
    }
    
    private static String getFormStringValue(Object formValue) {
        String strFormValue;
        
        if(formValue == null) {
            strFormValue = "";
        } else if (formValue instanceof Timestamp) {
            Timestamp t = (Timestamp) formValue;
            strFormValue = timestampDateFormat.format(new Date(t.getTime()));
        } else if (formValue instanceof Date) {
            strFormValue = timestampDateFormat.format(formValue);
        } else {
            strFormValue = formValue.toString();
        }

        Matcher m = itResourcePrefixPattern.matcher(strFormValue);
        if(m.find()) {
            System.out.println("*TRACE* Stripping OIM IT Resource prefix "+m.group()+" for value "+strFormValue);
            strFormValue = strFormValue.substring(m.end());
        }
        
        return strFormValue;
    }
    
    private List<User> searchUsers (Map<String, String> usersearchattributes) throws AccessDeniedException, UserSearchException, NoSuchAttributeException, ConfigManagerException, ParseException {
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
    
    private List<Role> searchRoles (Map<String, String> rolesearchattributes) throws AccessDeniedException, RoleSearchException, NoSuchAttributeException, ConfigManagerException, ParseException {
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
       
        return roleManager.search(searchCriteria, null, null);
    }
   
    private tcResultSet searchAccessPolicies (String policyname) throws tcAPIException {
        if (oimClient == null) {
            throw new RuntimeException("There is no connection to OIM");
        }
        tcAccessPolicyOperationsIntf polIntf = oimClient.getService(tcAccessPolicyOperationsIntf.class);
       
        Map<String,String> hm = new HashMap<>(1);
        hm.put("Access Policies.Name", policyname);
       
        System.out.println("*INFO* Searching for access policy having name '"+policyname+"'");
       
        return polIntf.findAccessPolicies(hm);
    }

    private String getUserLogin(String usrKey) throws UserLookupException, NoSuchUserException {
        if (oimClient == null) {
            throw new RuntimeException("There is no connection to OIM");
        }
        UserManager userManager = oimClient.getService(UserManager.class);

        Set<String> returnAttributes = new HashSet<>();
        returnAttributes.add(UserManagerConstants.AttributeName.USER_LOGIN.getId());

        User user = userManager.getDetails(usrKey, returnAttributes, false);

        return user.getLogin();
    }
}
