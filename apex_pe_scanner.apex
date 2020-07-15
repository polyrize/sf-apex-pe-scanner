List <PermissionSetAssignment> lstOfPSA = [SELECT id, AssigneeId
FROM PermissionSetAssignment
WHERE PermissionSet.PermissionsAuthorApex=true
  AND PermissionSet.PermissionsManageProfilesPermissionsets=false];

for(PermissionSetAssignment psa : lstOfPSA){
    List <PermissionSetAssignment> saAssingments = [SELECT id
       FROM PermissionSetAssignment
       WHERE AssigneeId=:psa.AssigneeId
         AND PermissionSet.PermissionsManageProfilesPermissionsets=true];
    if (saAssingments.size() == 0){
    	System.debug('User '+psa.AssigneeId);
    }
}