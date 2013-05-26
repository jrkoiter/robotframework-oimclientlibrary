/*
 * Copyright 20013 FuseLogic BV
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
 
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
 
import java.util.Map;
import java.util.Scanner;
import java.util.Set;
 
import javax.security.auth.login.LoginException;
 
import oracle.iam.identity.exception.RoleSearchException;
import oracle.iam.identity.rolemgmt.api.RoleManager;
import oracle.iam.identity.rolemgmt.api.RoleManagerConstants;
import oracle.iam.identity.rolemgmt.vo.Role;
import oracle.iam.platform.OIMClient;
import oracle.iam.platform.entitymgr.vo.SearchCriteria;
import oracle.iam.identity.rolemgmt.api.RoleManagerConstants.RoleAttributeName;
 
import oracle.iam.platform.authz.exception.AccessDeniedException;
 
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
 
import org.robotframework.javalib.annotation.ArgumentNames;
import org.robotframework.javalib.annotation.RobotKeyword;
import org.robotframework.javalib.annotation.RobotKeywords;
import org.robotframework.javalib.library.AnnotationLibrary;
 
@RobotKeywords
public class OimClientLibrary extends AnnotationLibrary {
   
    public static final String ROBOT_LIBRARY_VERSION = "0.2";
   
    private static enum JobStatus { SHUTDOWN, STARTED, STOPPED, NONE, PAUSED, RUNNING, FAILED, INTERRUPT }
   
    private static OIMClient        oimClient;
    private static RoleManager      roleManager;
    private static SchedulerService schedulerService;
    private static tcAccessPolicyOperationsIntf polIntf;
   
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
    public void connectToOim(String username, String password, String url) throws LoginException {
        if(oimClient != null) {
            System.out.println("*WARN* There is already a connection to OIM");
            return;
        }
       
        System.out.println("*INFO* Connecting to "+url+" as "+username);
       
        Hashtable env = new Hashtable();
        env.put(OIMClient.JAVA_NAMING_FACTORY_INITIAL, oimClient.WLS_CONTEXT_FACTORY);
        env.put(OIMClient.JAVA_NAMING_PROVIDER_URL, url);
       
        oimClient = new OIMClient(env);
        oimClient.login(username, password.toCharArray());
    }
   
    @RobotKeyword("Disconnect from OIM")
    public void disconnectFromOim() {
        if (oimClient == null) {
            System.out.println("*WARN* There is no connection to OIM");
            return;
        }
       
        oimClient.logout();
        oimClient = null;
        roleManager = null;
        schedulerService = null;
        polIntf = null;
    }
   
    @RobotKeyword("Fail if given rolename is not present in OIM")
    @ArgumentNames({"rolename"})
    public void oimShouldHaveRole(String rolename) throws AccessDeniedException, RoleSearchException {
       
        List<Role> roles = searchRoles(rolename);
       
        if(roles.size() == 0) {
            throw new RuntimeException("OIM does not have any role or roles that match the name '"+rolename+"'");
        }
    }
   
    @RobotKeyword("Fail if given rolename is present in OIM")
    @ArgumentNames({"rolename"})
    public void oimShouldNotHaveRole(String rolename) throws AccessDeniedException, RoleSearchException {
       
        List<Role> roles = searchRoles(rolename);
       
        if(roles.size() > 0) {
            throw new RuntimeException("OIM has one or more roles that match the name '"+rolename+"'");
        }
    }
   
    @RobotKeyword("Fail if given access policy is not present in OIM")
    @ArgumentNames({"policyname"})
    public void oimShouldHaveAccessPolicy(String policyname) throws tcAPIException, tcAPIException {
       
        tcResultSet policies = searchAccessPolicies(policyname);
       
        if(policies.getRowCount() == 0) {
            throw new RuntimeException("OIM does not have any access policy or policies that match the name '"+policyname+"'");
        }
    }
   
    @RobotKeyword("Fail if given access policy is present in OIM")
    @ArgumentNames({"policyname"})
    public void oimShouldNotHaveAccessPolicy(String policyname) throws tcAPIException, tcAPIException {
       
        tcResultSet policies = searchAccessPolicies(policyname);
       
        if(policies.getRowCount() > 0) {
            throw new RuntimeException("OIM has one or more access policies that match the name '"+policyname+"'");
        }
    }
   
    @RobotKeyword("Run the OIM scheduled job with given jobname")
    @ArgumentNames({"jobname"})
    public void runOimScheduledJob(String jobname) throws SchedulerException, SchedulerAccessDeniedException,
                                                          InterruptedException, NoJobHistoryFoundException {
        runJob(jobname, false);
    }
   
    @RobotKeyword("Run the OIM scheduled job with given jobname and wait for it to finish")
    @ArgumentNames({"jobname"})
    public void runOimScheduledJobAndWait(String jobname) throws SchedulerException, SchedulerAccessDeniedException,
                                                          InterruptedException, NoJobHistoryFoundException {
        runJob(jobname, true);
    }
   
    @RobotKeyword("Set a parameter on an OIM scheduled job")
    @ArgumentNames({"jobname","paramname","paramvalue"})
    public void setOimJobParameter(String jobname, String paramname, String paramvalue) throws SchedulerException, IncorrectScheduleTaskDefinationException, RequiredParameterNotSetException,
                                                                                               ParameterValueTypeNotSupportedException, LastModifyDateNotSetException, SchedulerAccessDeniedException {
        if (oimClient == null) {
            throw new RuntimeException("There is no connection to OIM");
        }
        if (schedulerService == null) {
            schedulerService = oimClient.getService(SchedulerService.class);
        }
       
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
   
    @RobotKeyword("Get a parameter value of an OIM scheduled job")
    @ArgumentNames({"jobname","paramname"})
    public String getOimJobParameter(String jobname, String paramname) throws SchedulerException, IncorrectScheduleTaskDefinationException {
        if (oimClient == null) {
            throw new RuntimeException("There is no connection to OIM");
        }
        if (schedulerService == null) {
            schedulerService = oimClient.getService(SchedulerService.class);
        }
       
        JobDetails jd = schedulerService.getJobDetail(jobname);
        JobParameter jp = jd.getParams().get(paramname);
       
        if(jp == null) {
            throw new RuntimeException("Job "+jobname+" has no parameter named "+paramname);
        }
       
        System.out.println("*INFO* Returning value " + jp.getValue().toString());
       
        return jp.getValue().toString();
    }
   
    private void runJob(String jobname, boolean wait) throws SchedulerException, SchedulerAccessDeniedException,
                                                             InterruptedException, NoJobHistoryFoundException {
        if (oimClient == null) {
            throw new RuntimeException("There is no connection to OIM");
        }
        if (schedulerService == null) {
            schedulerService = oimClient.getService(SchedulerService.class);
        }
       
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
   
    private List<Role> searchRoles (String rolename) throws AccessDeniedException, RoleSearchException {
        if (oimClient == null) {
            throw new RuntimeException("There is no connection to OIM");
        }
        if (roleManager == null) {
            roleManager = oimClient.getService(RoleManager.class);
        }
       
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
        if (polIntf == null) {
            polIntf = oimClient.getService(tcAccessPolicyOperationsIntf.class);
        }
       
        Map<String,String> hm = new HashMap<String,String>();
        hm.put("Access Policies.Name", policyname);
       
        System.out.println("*INFO* Searching for access policy having name '"+policyname+"'");
       
        tcResultSet ts = polIntf.findAccessPolicies(hm);
       
        return ts;
    }
}
