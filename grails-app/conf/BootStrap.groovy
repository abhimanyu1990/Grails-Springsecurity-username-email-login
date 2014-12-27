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
			String salt = saltSource instanceof NullSaltSource ? null : "SUPERADMIN"
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
