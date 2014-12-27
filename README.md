Grails-Springsecurity-username-email-login
==========================================

This seed is to configure spring security in your application and to enable login vai either using username or email
Grails spring security plugin supports login via username only . If you need to enable login via username or password you have to configure spring-security-core plugin services and controller.


I am using Grails version 2.4.4.

Below are the steps for configuration.

Step 1 - Install spring-security-core plugin by editing BuildConfig.groovy file in your conf directory .
```
plugins {
        // plugins for the build system only
        build ":tomcat:7.0.55"
	    	compile ":spring-security-core:2.0-RC4"
		    compile ":spring-security-ui:1.0-RC2"
		    compile ":jquery:1.11.1"
		    compile ":jquery-ui:1.10.4"
	    	compile ":famfamfam:1.0.1"
		    compile ":mail:1.0.7"
        // plugins needed at runtime but not for compilation
        runtime ":hibernate4:4.3.6.1" // or ":hibernate:3.6.10.18"
        runtime ":database-migration:1.4.0"
    }
```



Step 2 -  use s2-quickstart script provided by spring-security-core plugin to create your domains
            ```
             s2-quickstart <package> <domain1> <domain2>
             
             I have created User and Role domain  s2-quickstart com.abhimanyu.example.auth User Role
             It will create three domain User , Role and UserRole
             User will constain account related information username , password , enabled , accountLocked etc
             Role will contain the authorities available in your application
             UserRole contains the authorities available to each user
             
             It will add following line into Config.groovy
             ```
             ```
             grails.plugin.springsecurity.userLookup.userDomainClassName = 'com.abhimanyu.example.auth.User'
             grails.plugin.springsecurity.userLookup.authorityJoinClassName = 'com.abhimanyu.example.auth.UserRole'
             grails.plugin.springsecurity.authority.className = 'com.abhimanyu.example.auth.Role'
             grails.plugin.springsecurity.controllerAnnotations.staticRules = [
	              '/':                              ['permitAll'],
	              '/index':                         ['permitAll'],
	              '/index.gsp':                     ['permitAll'],
	              '/assets/**':                     ['permitAll'],
	              '/**/js/**':                      ['permitAll'],
	              '/**/css/**':                     ['permitAll'],
	              '/**/images/**':                  ['permitAll'],
	              '/**/favicon.ico':                ['permitAll']
            ]
            ```
Step 3 - configure your mail plugin , add configuration details in Config.groovy file 
ref : - http://grails.org/plugin/mail
```
grails {
   mail {
     host = "smtp.gmail.com"
     port = 465
     username = "youracount@gmail.com"
     password = "yourpassword"
     props = ["mail.smtp.auth":"true", 					   
              "mail.smtp.socketFactory.port":"465",
              "mail.smtp.socketFactory.class":"javax.net.ssl.SSLSocketFactory",
              "mail.smtp.socketFactory.fallback":"false"]
   }
}
```
overide the subject for registration email , add below line to Config.groovy
```
grails.plugins.springsecurity.ui.register.emailSubject = 'Welcome to Organization' 
```
To change the email body for forgotPassword , resetPassword and registration emai , add and edit below line in config.groovy
```
grails.plugin.springsecurity.ui.register.emailBody =’ email body’
grails.plugin.springsecurity.ui.forgotPassword.emailBody ='body'
grails.plugin.springsecurity.ui.resetPassword.emailBody ='body'
```
Configuration of post destination url is  in grails-app/conf/Config.groovy 
```
grails.plugin.springsecurity.ui.register.postRegisterUrl= '/welcome'
grails.plugin.springsecurity.ui.forgotPassword.postResetUrl = '/welcome'
```
- 
Step 4 - Now we have to edit User domain as there is no "email" field in it 
         Add String email in your user domain 
         
         your User domain should look like 
  ```       
  class User {

	transient springSecurityService

	String username
	String password
	String email
	boolean enabled = true
	boolean accountExpired
	boolean accountLocked
	boolean passwordExpired

	static transients = ['springSecurityService']

	static constraints = {
		username blank: false, unique: true
		password blank: false
		email email: true, blank: false
	}

	static mapping = {
		password column: '`password`'
	}

	Set<Role> getAuthorities() {
		UserRole.findAllByUser(this).collect { it.role }
	}

<!--	def beforeInsert() {
		encodePassword()
	}

	def beforeUpdate() {
		if (isDirty('password')) {
			encodePassword()
		}
	}-->

	<!--protected void encodePassword() {
		password = springSecurityService?.passwordEncoder ? springSecurityService.encodePassword(password) : password
	}-->
}
```
Step 5 - Now Edit you bootStrap.groovy 
         Write code to add Role and Admin user to your application . I have added a user with email "abhimanyu.mailme@gmail.com" , username = "SUPERADMIN" , password = "root"
         
 Your BootStrap.groovy will look be like 
 ```         
import com.abhimanyu.example.auth.Role
import com.abhimanyu.example.auth.User
import com.abhimanyu.example.auth.UserRole
import grails.plugin.springsecurity.authentication.dao.NullSaltSource

class BootStrap {

  def saltSource
	def springSecurityService
	def grailsApplication
    def init = { servletContext ->
		if(Role.list().size() == 0){
				new Role(authority:"ROLE_SUPERADMIN").save()
				new Role(authority:"ROLE_ADMIN").save()
					
		}
				
    if(User.list().size() == 0){
			String salt = saltSource instanceof NullSaltSource ? null : "SUPERADMIN" // spring security use username as salt for password encryption
			String encodedPassword = springSecurityService.encodePassword('root',salt)
			def superUser = new User( email:"abhimanyu.mailme@gmail.com",
				    				password:encodedPassword,
									  accountLocked: false,
									  enabled: true,
									  accountExpired:false,
									  passwordExpired:false,
									  username:"SUPERADMIN",
									)
			superUser.save()
			superUser.errors.each{
				println it
			}
			def role = new UserRole(user:superUser,role:Role.findWhere(authority:'ROLE_SUPERADMIN')).save();
			}
	
    }
    def destroy = {
    }
}
```
Step 6 : Try to login with email and password for Admin user , you will be not allowed to login 

Step 7 : Try to login with username and password for Admin user, you will be immediately login to application

Step 8 : Now we need to configure our application to use either email or username to login to application

Create a service CustomUserDetailsService which extends GormUserDetailsService
```
package com.abhimanyu.example.auth

import grails.plugin.springsecurity.userdetails.GormUserDetailsService
import grails.plugin.springsecurity.userdetails.GrailsUser
import grails.transaction.Transactional
import org.springframework.security.core.authority.GrantedAuthorityImpl
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UsernameNotFoundException
import grails.plugin.springsecurity.SpringSecurityUtils

@Transactional
class CustomUserDetailsService extends GormUserDetailsService{

     static final List NO_ROLES = [new GrantedAuthorityImpl(SpringSecurityUtils.NO_ROLE)]

   UserDetails loadUserByUsername(String username, boolean loadRoles)
			throws UsernameNotFoundException {
				return loadUserByUsername(username)
   }

   UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

	  User.withTransaction { status ->

	  User user = User.findByUsernameOrEmail(username,username)  //enable login with either username or password
		 
		 if (!user) throw new UsernameNotFoundException(
					  'User not found', username)

		 def authorities = user.authorities.collect {
			 new GrantedAuthorityImpl(it.authority)
		 }

		  return new GrailsUser(user.username,
			  		user.password,
                    user.enabled,
                    !user.accountExpired,
                    !user.passwordExpired,
                    !user.accountLocked,
                    authorities ?: NO_ROLES,
                    user.id)

	  }
   }
}
```

Step 9 . Now override UserDetailsService bean provided by spring security  with our CustomUserDetailsService in resource.groovy file
```
beans = {
	userDetailsService(com.abhimanyu.example.auth.CustomUserDetailsService){
		grailsApplication = ref('grailsApplication')
	}
}
```
Step 10 . now you could login with either email or username for login.
         
         
