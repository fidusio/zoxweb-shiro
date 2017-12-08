package org.zoxweb.server.security.shiro;

import java.util.List;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.UnavailableSecurityManagerException;
import org.apache.shiro.subject.Subject;

import org.zoxweb.server.security.CryptoUtil;
import org.zoxweb.server.security.KeyMakerProvider;
import org.zoxweb.server.security.shiro.authc.DomainUsernamePasswordToken;
import org.zoxweb.server.security.shiro.authc.JWTAuthenticationToken;
import org.zoxweb.shared.api.APICredentialsDAO;
import org.zoxweb.shared.api.APIDataStore;
import org.zoxweb.shared.api.APISecurityManager;
import org.zoxweb.shared.api.APITokenDAO;
import org.zoxweb.shared.crypto.EncryptedDAO;
import org.zoxweb.shared.crypto.EncryptedKeyDAO;
import org.zoxweb.shared.data.DataConst.SessionParam;
import org.zoxweb.shared.data.MessageTemplateDAO;
import org.zoxweb.shared.data.UserIDDAO;
import org.zoxweb.shared.db.QueryMarker;
import org.zoxweb.shared.filters.BytesValueFilter;
import org.zoxweb.shared.filters.ChainedFilter;
import org.zoxweb.shared.filters.FilterType;
import org.zoxweb.shared.security.AccessException;
import org.zoxweb.shared.security.JWTToken;
import org.zoxweb.shared.security.model.SecurityModel;
import org.zoxweb.shared.security.shiro.ShiroAssociationDAO;
import org.zoxweb.shared.security.shiro.ShiroAssociationRuleDAO;
import org.zoxweb.shared.security.shiro.ShiroAssociationType;
import org.zoxweb.shared.security.shiro.ShiroCollectionAssociationDAO;
import org.zoxweb.shared.security.shiro.ShiroDAO;
import org.zoxweb.shared.security.shiro.ShiroPermissionDAO;
import org.zoxweb.shared.security.shiro.ShiroRoleDAO;
import org.zoxweb.shared.security.shiro.ShiroRoleGroupDAO;
import org.zoxweb.shared.security.shiro.ShiroSubjectDAO;
import org.zoxweb.shared.util.ArrayValues;
import org.zoxweb.shared.util.CRUD;
import org.zoxweb.shared.util.Const.LogicalOperator;
import org.zoxweb.shared.util.NVBase;
import org.zoxweb.shared.util.NVConfig;
import org.zoxweb.shared.util.NVEntity;
import org.zoxweb.shared.util.NVEntityGetNameMap;
import org.zoxweb.shared.util.NVEntityReference;
import org.zoxweb.shared.util.NVEntityReferenceIDMap;
import org.zoxweb.shared.util.NVEntityReferenceList;
import org.zoxweb.shared.util.NVPair;
import org.zoxweb.shared.util.SharedStringUtil;
import org.zoxweb.shared.util.SharedUtil;
import org.zoxweb.shared.util.NVConfigEntity;

public class APISecurityManagerProvider
	implements  APISecurityManager<Subject>
{
	
	protected static final transient Logger log = Logger.getLogger(APISecurityManagerProvider.class.getName());
	
	private final AtomicReference<Subject> daemon = new AtomicReference<Subject>();
	

	@Override
	public final Object encryptValue(APIDataStore<?> dataStore, NVEntity container, NVConfig nvc, NVBase<?> nvb, byte[] msKey)
			throws NullPointerException, IllegalArgumentException, AccessException {
		SharedUtil.checkIfNulls("Null parameters", container != null ? container.getReferenceID() : container, nvb);
		
		
		
		boolean encrypt = false;
		
//		System.out.println("NVC:"+nvc);
//		System.out.println("NVB:"+nvb);
		
		// the nvpair filter will override nvc value
		if (nvb instanceof NVPair && 
			(ChainedFilter.isFilterSupported(((NVPair)nvb).getValueFilter(),FilterType.ENCRYPT) || ChainedFilter.isFilterSupported(((NVPair)nvb).getValueFilter(),FilterType.ENCRYPT_MASK)))
		{
			encrypt = true;
			
			//System.out.println("NVB Filter:"+((NVPair)nvb).getValueFilter().toCanonicalID());
		}
		else if (nvc != null && (ChainedFilter.isFilterSupported(nvc.getValueFilter(), FilterType.ENCRYPT) || ChainedFilter.isFilterSupported(nvc.getValueFilter(), FilterType.ENCRYPT_MASK)))
		{
			encrypt = true;
			//System.out.println("NVC Filter:"+nvc.getValueFilter());
		}
		
		
		
//		System.out.println("NVC:"+nvc);
//		System.out.println("NVB:"+nvb);
//		System.out.println("Encrypt:"+encrypt);
		
		if (encrypt && nvb.getValue() != null)
		{
//			CRUD toCheck [] = null;
//			if (container.getReferenceID() != null)
//			{
//				toCheck = new CRUD[]{CRUD.UPDATE};
//			}
//			else
//			{
//				toCheck = new CRUD[]{CRUD.CREATE, CRUD.UPDATE};
//			}
			
			// CRUD.MOVE was to allow shared with to move the data between folders
			byte dataKey[] = KeyMakerProvider.SINGLETON.getKey(dataStore, msKey, checkNVEntityAccess(LogicalOperator.OR, container, CRUD.MOVE, CRUD.UPDATE, CRUD.CREATE), container.getReferenceID());
			try
			{
				return CryptoUtil.encryptDAO(new EncryptedDAO(), dataKey, BytesValueFilter.SINGLETON.validate(nvb));
				
			} catch (InvalidKeyException | NullPointerException
					| IllegalArgumentException | NoSuchAlgorithmException
					| NoSuchPaddingException
					| InvalidAlgorithmParameterException
					| IllegalBlockSizeException | BadPaddingException e)
			{
				// TODO Auto-generated catch block
				throw new AccessException(e.getMessage());
			}
		}
		else
		{
			return nvb.getValue();
		}
	}
	
	
	protected ShiroBaseRealm getShiroBaseRealm()
	{
		return ShiroUtil.getRealm(ShiroBaseRealm.class);
	}

	@SuppressWarnings("unchecked")
	@Override
	public final NVEntity decryptValues(APIDataStore<?> dataStore, NVEntity container, byte msKey[])
		throws NullPointerException, IllegalArgumentException, AccessException
	{
		
		if (container == null)
		{
			return null;
		}
		
		SharedUtil.checkIfNulls("Null parameters", container != null ? container.getReferenceID() : container);
		for (NVBase<?> nvb : container.getAttributes().values().toArray( new NVBase[0]))
		{
			if (nvb instanceof NVPair)
			{
				decryptValue(dataStore, container, (NVPair)nvb, null);
			}
			else if (nvb instanceof NVEntityReference)
			{
				NVEntity temp = (NVEntity) nvb.getValue();
				if (temp != null)
				{
					decryptValues(dataStore, temp, null);
				}
			}
			else if (nvb instanceof NVEntityReferenceList || nvb instanceof NVEntityReferenceIDMap || nvb instanceof NVEntityGetNameMap)
			{
				ArrayValues<NVEntity> arrayValues = (ArrayValues<NVEntity>) nvb;
				for (NVEntity nve : arrayValues.values())
				{
					if (nve != null)
					{
						decryptValues(dataStore, container, null);
					}
				}
			}
		}
		
		
		return container;
		
	}
	
	@Override
	public final String decryptValue(APIDataStore<?> dataStore, NVEntity container, NVPair nvp, byte msKey[])
			throws NullPointerException, IllegalArgumentException, AccessException
		{
		
			if (container instanceof EncryptedDAO)
			{
				return nvp != null ? nvp.getValue() : null;
			}
		
		
			SharedUtil.checkIfNulls("Null parameters", container != null ? container.getReferenceID() : container, nvp);
			
			if (nvp.getValue()!= null && (ChainedFilter.isFilterSupported(nvp.getValueFilter(), FilterType.ENCRYPT) || ChainedFilter.isFilterSupported(nvp.getValueFilter(), FilterType.ENCRYPT_MASK)))
			{
				
				byte dataKey[] = KeyMakerProvider.SINGLETON.getKey(dataStore, msKey, checkNVEntityAccess(container, CRUD.READ), container.getReferenceID());
				try
				{
					EncryptedDAO ed = EncryptedDAO.fromCanonicalID(nvp.getValue());
					byte data[] = CryptoUtil.decryptEncryptedDAO(ed, dataKey);
					
					nvp.setValue( new String(data, SharedStringUtil.UTF_8));
					return nvp.getValue();
					
					
				} catch (NullPointerException
						| IllegalArgumentException | UnsupportedEncodingException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | SignatureException  e)
				{
					// TODO Auto-generated catch block
					throw new AccessException(e.getMessage());
				}
			}
			else
			{
				return nvp.getValue();
			}
		}
	
	
	@Override
	public final Object decryptValue(APIDataStore<?> dataStore, NVEntity container, NVBase<?> nvb, Object value, byte msKey[])
			throws NullPointerException, IllegalArgumentException, AccessException
	{
	
		if (container instanceof EncryptedDAO && !(container instanceof EncryptedKeyDAO))
		{
			container.setValue(nvb.getName(), value);
			return nvb.getValue();
		}
	
	
		SharedUtil.checkIfNulls("Null parameters", container != null ? container.getReferenceID() : container, nvb);
		NVConfig nvc = ((NVConfigEntity)container.getNVConfig()).lookup(nvb.getName());
		
		if (value instanceof EncryptedDAO && (ChainedFilter.isFilterSupported(nvc.getValueFilter(), FilterType.ENCRYPT) || ChainedFilter.isFilterSupported(nvc.getValueFilter(), FilterType.ENCRYPT_MASK)))
		{
			
			byte dataKey[] = KeyMakerProvider.SINGLETON.getKey(dataStore, msKey, checkNVEntityAccess(container, CRUD.READ), container.getReferenceID());
			try
			{
				
				byte data[] = CryptoUtil.decryptEncryptedDAO((EncryptedDAO) value, dataKey);
				
				BytesValueFilter.setByteArrayToNVBase(nvb, data);
				
			
				return nvb.getValue();
				
				
			} catch (NullPointerException
					| IllegalArgumentException  | InvalidKeyException
					| NoSuchAlgorithmException | NoSuchPaddingException
					| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | SignatureException  e)
			{
				// TODO Auto-generated catch block
				e.printStackTrace();
				throw new AccessException(e.getMessage());
			}
		}
		else
		{
		
			return value;
		}
	}
	
	@Override
	public final Object decryptValue(String userID, APIDataStore<?> dataStore, NVEntity container, Object value, byte msKey[])
			throws NullPointerException, IllegalArgumentException, AccessException
	{
	
		if (container instanceof EncryptedDAO && !(container instanceof EncryptedKeyDAO))
		{
			
			return value;
		}
	
	
		SharedUtil.checkIfNulls("Null parameters", container != null ? container.getReferenceID() : container);
		
		if (value instanceof EncryptedDAO)
		{
			//log.info("userID:" + userID);
			
			byte dataKey[] = KeyMakerProvider.SINGLETON.getKey(dataStore, msKey, (userID != null ?  userID : checkNVEntityAccess(container, CRUD.READ)), container.getReferenceID());
			try
			{
				
				byte data[] = CryptoUtil.decryptEncryptedDAO((EncryptedDAO) value, dataKey);
				return BytesValueFilter.bytesToValue(String.class, data);
				
				
			} catch (NullPointerException
					| IllegalArgumentException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | SignatureException  e)
			{
				// TODO Auto-generated catch block
				e.printStackTrace();
				throw new AccessException(e.getMessage());
			}
		}
		else
		{
		
			return value;
		}
	}

	@Override
	public final void associateNVEntityToSubjectUserID(NVEntity nve, String userID) {
		// TODO Auto-generated method stub
		if (nve.getReferenceID() == null)
		{
			if (nve.getUserID() == null)
			{
				if (userID != null)
				try
				{
					SecurityUtils.getSecurityManager();
				}
				catch(UnavailableSecurityManagerException e)
				{
					return;
				}
				
				
				/// must create a exclusion filter
				if (!(nve instanceof UserIDDAO || nve instanceof MessageTemplateDAO))
					nve.setUserID(userID != null ? userID : currentUserID());
				
				for (NVBase<?> nvb : nve.getAttributes().values().toArray( new NVBase[0]))
				{
					if (nvb instanceof NVEntityReference)
					{
						NVEntity temp = (NVEntity) nvb.getValue();
						if (temp != null)
						{
							associateNVEntityToSubjectUserID(temp, userID);
						}
					}
					else if (nvb instanceof NVEntityReferenceList || nvb instanceof NVEntityReferenceIDMap || nvb instanceof NVEntityGetNameMap)
					{
						@SuppressWarnings("unchecked")
						ArrayValues<NVEntity> arrayValues = (ArrayValues<NVEntity>) nvb;
						for (NVEntity nveTemp : arrayValues.values())
						{
							if (nveTemp != null)
							{
								associateNVEntityToSubjectUserID(nveTemp, userID);
							}
						}
					}
				}	
				
			}
		}
	}

	@Override
	public final String currentSubjectID()
			throws AccessException
	{
		// TODO Auto-generated method stub
		return (String) SecurityUtils.getSubject().getPrincipal();
	}
	
	public final String currentDomainID()
			throws AccessException
	{
		return ShiroUtil.subjectDomainID();
	}
	
	public final String currentAppID()
			throws AccessException
	{
		return ShiroUtil.subjectAppID();
	}
	
	
	
	

	@Override
	public final String currentUserID()
			throws AccessException
	{
		// new code
		
		String userID = (String) SecurityUtils.getSubject().getSession().getAttribute(SessionParam.USER_ID.getName());
		if (userID == null)
		{
			userID = ShiroUtil.subjectUserID();
		}
//		try
//		{
//			SecurityUtils.getSecurityManager();
//
//			if (userID == null)
//			{
//				userID = ShiroUtil.subjectUserID();
//			}
//		}
//		catch(UnavailableSecurityManagerException e)
//		{
//		}
		return userID;
	}

	@Override
	public final Subject getDaemonSubject()
	{
		return daemon.get();
	}
	
	
	
	public final void setDaemonSubject(Subject subject)
	{
		if (subject != null && daemon.get() == null)
		{
			if (daemon.get() == null)
			{
				daemon.set(subject);
			}
		}
	}

	@Override
	public final  boolean isNVEntityAccessible(NVEntity nve, CRUD ...permissions)
			throws NullPointerException, IllegalArgumentException
	{
		return isNVEntityAccessible(LogicalOperator.AND, nve, permissions);
	}
	
	@Override
	public final  boolean isNVEntityAccessible(LogicalOperator lo, NVEntity nve, CRUD ...permissions)
		throws NullPointerException, IllegalArgumentException
	{
		try
		{
			checkNVEntityAccess(lo, nve, permissions);
			return true;
		}
		catch(AccessException e)
		{
			//e.printStackTrace();
			return false;
		}
	}
	
	@Override
	public final String checkNVEntityAccess(NVEntity nve, CRUD ...permissions)
			throws NullPointerException, IllegalArgumentException, AccessException
	
	{
		return checkNVEntityAccess(LogicalOperator.AND, nve, permissions);
	}
	
	@Override
	public final  String checkNVEntityAccess(LogicalOperator lo, NVEntity nve, CRUD ...permissions)
		throws NullPointerException, IllegalArgumentException, AccessException
	{
		SharedUtil.checkIfNulls("Null NVEntity", lo, nve);
		
		if (nve instanceof APICredentialsDAO || nve instanceof APITokenDAO)
		{
			return nve.getUserID();
		}
		
		String userID = currentUserID();
		
		if (userID == null || nve.getUserID() == null)
		{
			throw new AccessException("Unauthenticed subject: " + nve.getClass().getName());
		}
		
		if (!nve.getUserID().equals(userID))
		{
			
			if (permissions != null && permissions.length > 0)
			{
				boolean checkStatus = false;
				for(CRUD permission : permissions)
				{
					checkStatus = ShiroUtil.isPermitted(SharedUtil.toCanonicalID(':', "nventity", permission, nve.getReferenceID()));
				
					if ((checkStatus && LogicalOperator.OR == lo) ||
						(!checkStatus && LogicalOperator.AND == lo))
					{
						// we are ok
						break;
					}
					
				}
				if(checkStatus)
					return nve.getUserID();
			}
			
			log.info("nveUserID:" + nve.getUserID() + " userID:" + userID);
			throw new AccessException("Access Denied. for resource:" + nve.getReferenceID());
		}
		
		return userID;
	}
	
	
	

	@Override
	public final boolean isNVEntityAccessible(String nveRefID, String nveUserID, CRUD... permissions) {
		SharedUtil.checkIfNulls("Null reference ID.", nveRefID);
		
		String userID = currentUserID();
		
		if (userID != null && nveUserID != null)
		{
			if (!nveUserID.equals(userID))
			{
				if (permissions != null && permissions.length > 0)
				{
	
					for(CRUD permission : permissions)
					{
						if (!ShiroUtil.isPermitted(SharedUtil.toCanonicalID(':', "nventity", permission, nveRefID)))
						{
							return false;
						}
					}
					
					return true;
				}
				
				//log.info("NVEntity UserID:" + nveUserID + " UserID:" + userID);		
			}
			else
			{
				return true;
			}
		}
		
		return false;
	}
	
	@Override
	public final void checkSubject(String subjectID)
			throws NullPointerException, AccessException
	{
		SharedUtil.checkIfNulls("subjectID null", subjectID);
		if(!SecurityUtils.getSubject().isAuthenticated() && !SecurityUtils.getSubject().getPrincipal().equals(subjectID))
		{
			throw new AccessException("Access denied");
			
		}
	}
	
	
	@Override
	public final  String checkNVEntityAccess(String nveRefID, String nveUserID, CRUD ...permissions)
			throws NullPointerException, IllegalArgumentException, AccessException
	{
		SharedUtil.checkIfNulls("Null reference ID.", nveRefID);
		
		String userID = currentUserID();
		
		if (userID == null || nveUserID == null)
		{
			throw new AccessException("Unauthenticed subject.");
		}
		
		if (!nveUserID.equals(userID))
		{
			if (permissions != null && permissions.length > 0)
			{

				for(CRUD permission : permissions)
				{
					ShiroUtil.checkPermissions(SharedUtil.toCanonicalID(':', "nventity", permission, nveRefID));
				}
				
				return nveUserID;
			}
			
			log.info("NVEntity UserID:" + nveUserID + " UserID:" + userID);
			
			throw new AccessException("Unauthorized subject");
		}
		
		return userID;
	}
	
	@Override
	public final  String checkNVEntityAccess(String nveRefID, CRUD ...permissions)
		throws NullPointerException, IllegalArgumentException, AccessException
	{
		SharedUtil.checkIfNulls("Null reference ID.", nveRefID);
		
		String userID = currentUserID();
		
		if (userID == null)
		{
			throw new AccessException("Unauthenticed subject.");
		}
		
		if (!userID.equals(userID))
		{
			if (permissions != null && permissions.length > 0)
			{

				for(CRUD permission : permissions)
				{
					ShiroUtil.checkPermissions(SharedUtil.toCanonicalID(':', "nventity", permission, nveRefID));
				}
				
				return userID;
			}
			
			log.info("NVEntity refID:" + nveRefID + " UserID:" + userID);
			
			throw new AccessException("Unauthorized subject");
		}
		
		return userID;
	}

	@Override
	public Subject login(String subjectID, String credentials, String domainID, String appID, boolean autoLogin) 
	{
		Subject currentUser = SecurityUtils.getSubject();
	    if (!currentUser.isAuthenticated() )
	    {
	        //collect user principals and credentials in a gui specific manner
	        //such as username/password html form, X509 certificate, OpenID, etc.
	        //We'll use the username/password example here since it is the most common.
	    	DomainUsernamePasswordToken token = new DomainUsernamePasswordToken(subjectID, credentials, false, null, domainID, appID);
	        token.setAutoAuthenticationEnabled(autoLogin);

	        //this is all you have to do to support 'remember me' (no config - built in!):
	        token.setRememberMe(true);

	        currentUser.login(token);
	        log.info(""+SecurityUtils.getSubject().getPrincipals().getClass());
	    }   
		return currentUser;
	}
	
	
	public Subject login(JWTToken jwtToken) 
	{
		Subject currentUser = SecurityUtils.getSubject();
	    if (!currentUser.isAuthenticated())
	    {
	        //collect user principals and credentials in a gui specific manner
	        //such as username/password html form, X509 certificate, OpenID, etc.
	        //We'll use the username/password example here since it is the most common.
	    	
	        currentUser.login(new JWTAuthenticationToken(jwtToken));
	        //log.info(""+SecurityUtils.getSubject().getPrincipals().getClass());
	    }   
		return currentUser;
	}

	@Override
	public void logout() 
	{
		// TODO Auto-generated method stub
		SecurityUtils.getSubject().logout();
	}

	@Override
	public String currentJWTSubjectID() throws AccessException
	{
		// TODO Auto-generated method stub
		return ShiroUtil.subjectJWTID();
	}

	@Override
	public ShiroSubjectDAO addSubject(ShiroSubjectDAO subject)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return getShiroBaseRealm().addSubject(subject);
	}

	@Override
	public ShiroSubjectDAO deleteSubject(ShiroSubjectDAO subject, boolean withRoles)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return  getShiroBaseRealm().deleteSubject(subject, withRoles);
	}

	@Override
	public ShiroSubjectDAO updateSubject(ShiroSubjectDAO subject)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return  getShiroBaseRealm().updateSubject(subject);
	}

	@Override
	public ShiroRoleDAO addRole(ShiroRoleDAO role)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		checkPermissions(SecurityModel.Permission.ADD_ROLE.getValue());
		return  getShiroBaseRealm().addRole(role);
	}

	@Override
	public ShiroRoleDAO lookupRole(String roleID)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		
		return  getShiroBaseRealm().lookupRole(roleID);
	}

	@Override
	public ShiroRoleDAO deleteRole(ShiroRoleDAO role, boolean withPermissions)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		checkPermissions(SecurityModel.Permission.DELETE_ROLE.getValue());
		return  getShiroBaseRealm().deleteRole(role, withPermissions);
	}

	@Override
	public ShiroRoleDAO updateRole(ShiroRoleDAO role)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		checkPermissions(SecurityModel.Permission.UPDATE_ROLE.getValue());
		return  getShiroBaseRealm().updateRole(role);
	}

	@Override
	public ShiroRoleGroupDAO addRoleGroup(ShiroRoleGroupDAO rolegroup)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return  getShiroBaseRealm().addRoleGroup(rolegroup);
	}

	@Override
	public ShiroRoleGroupDAO deleteRoleGroup(ShiroRoleGroupDAO rolegroup)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return  getShiroBaseRealm().deleteRoleGroup(rolegroup);
	}

	@Override
	public ShiroRoleGroupDAO updateRoleGroup(ShiroRoleGroupDAO rolegroup)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return  getShiroBaseRealm().updateRoleGroup(rolegroup);
	}

	@Override
	public ShiroPermissionDAO addPermission(ShiroPermissionDAO permission)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		checkPermissions(SecurityModel.Permission.ADD_PERMISSION.getValue());
		return  getShiroBaseRealm().addPermission(permission);
	}

	@Override
	public ShiroPermissionDAO lookupPermission(String permissionID)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return  getShiroBaseRealm().lookupPermission(permissionID);
	}

	@Override
	public ShiroPermissionDAO deletePermission(ShiroPermissionDAO permission)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		checkPermissions(SecurityModel.Permission.DELETE_PERMISSION.getValue());
		return  getShiroBaseRealm().deletePermission(permission);
	}

	@Override
	public ShiroPermissionDAO updatePermission(ShiroPermissionDAO permission)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		checkPermissions(SecurityModel.Permission.UPTDATE_PERMISSION.getValue());
		return  getShiroBaseRealm().updatePermission(permission);
	}

	@Override
	public List<ShiroSubjectDAO> getAllShiroSubjects() throws AccessException {
		// TODO Auto-generated method stub
		return  getShiroBaseRealm().getAllShiroSubjects();
	}

	@Override
	public List<ShiroRoleDAO> getAllShiroRoles() throws AccessException {
		// TODO Auto-generated method stub
		return  getShiroBaseRealm().getAllShiroRoles();
	}

	@Override
	public List<ShiroRoleGroupDAO> getAllShiroRoleGroups() throws AccessException {
		// TODO Auto-generated method stub
		return  getShiroBaseRealm().getAllShiroRoleGroups();
	}

	@Override
	public List<ShiroPermissionDAO> getAllShiroPermissions() throws AccessException {
		// TODO Auto-generated method stub
		return  getShiroBaseRealm().getAllShiroPermissions();
	}

	@Override
	public ShiroSubjectDAO lookupSubject(String userName)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return  getShiroBaseRealm().lookupSubject(userName);
	}

	@Override
	public ShiroCollectionAssociationDAO lookupShiroCollection(ShiroDAO shiroDao, ShiroAssociationType sat)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return  getShiroBaseRealm().lookupShiroCollection(shiroDao, sat);
	}

	@Override
	public ShiroAssociationDAO addShiroAssociationDAO(ShiroAssociationDAO association)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return addShiroAssociationDAO(association);
	}

	@Override
	public ShiroAssociationDAO removeShiroAssociationDAO(ShiroAssociationDAO association)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return  getShiroBaseRealm().removeShiroAssociationDAO(association);
	}


	@Override
	public void addShiroRule(ShiroAssociationRuleDAO sard) {
		// TODO Auto-generated method stub
		getShiroBaseRealm().addShiroRule(sard);
	}


	@Override
	public void deleteShiroRule(ShiroAssociationRuleDAO sard) {
		// TODO Auto-generated method stub
		getShiroBaseRealm().deleteShiroRule(sard);
	}


	@Override
	public void updateShiroRule(ShiroAssociationRuleDAO sard) {
		// TODO Auto-generated method stub
		getShiroBaseRealm().updateShiroRule(sard);
	}


	@Override
	public List<ShiroAssociationRuleDAO> search(QueryMarker... queryCriteria) {
		// TODO Auto-generated method stub
		return getShiroBaseRealm().search(queryCriteria);
	}

	
	public final void checkPermissions(String ...permissions)
			 throws NullPointerException, IllegalArgumentException, AccessException
	{
		ShiroUtil.checkPermissions(permissions);
	}

	@Override
	public final boolean hasPermission(String permission)
			throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return ShiroUtil.isPermitted(permission);
	}


	@Override
	public final void checkRoles(String... roles) throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		ShiroUtil.checkRoles(roles);
	}

	/**
	 * Check the id the suer has the role
	 */
	@Override
	public final boolean hasRole(String role) throws NullPointerException, IllegalArgumentException, AccessException {
		// TODO Auto-generated method stub
		return SecurityUtils.getSubject().hasRole(role);
	}
	
	
}
