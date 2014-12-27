// Place your Spring DSL code here
beans = {
	userDetailsService(com.abhimanyu.example.auth.CustomUserDetailsService){
		grailsApplication = ref('grailsApplication')
	}
}
