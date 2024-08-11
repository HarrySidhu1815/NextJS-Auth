'use server'

import { createAuthSession, destroySession } from "@/lib/auth-session"
import { hashUserPassword, verifyPassword } from "@/lib/hash"
import { createUser, getUserByEmail } from "@/lib/users"
import { redirect } from "next/navigation"

export const signup = async (prevState, formData) => {
    const email = formData.get('email')
    const password = formData.get('password')

    let errors = {}

    if(!email.includes('@')){
        errors.email = 'Please enter the correct email address.'
    }

    if(password.trim().length < 8){
        errors.password = 'Please enter the password having length more than 8.'
    }

    if(Object.keys(errors).length > 0){
        return {
            errors
        }
    }
    const hashedPassword = hashUserPassword(password)
    
    try {
        const userId = createUser(email, hashedPassword)
        await createAuthSession(userId)
        redirect('/training')
    } catch (error) {
        if(error.code === 'SQLITE_CONSTRAINT_UNIQUE'){
            return {
                errors : {
                    email: 'This email is already registered. Please Login in'
                }
            }
        }

        throw error
    }
}

export async function login(prevState, formData) {
    const email = formData.get('email')
    const password = formData.get('password')

    const existingUser = getUserByEmail(email)

    if(!existingUser){
        return {
            errors: {
                email: 'Could not autheniticate the user. Please Sign Up'
            }
        }
    }

    const isValidPassword = verifyPassword(existingUser.password, password)

    if(!isValidPassword){
        return {
            errors: {
                password: 'Wrong Credential. Please check the credentials.'
            }
        }
    }

    await createAuthSession(existingUser.id)
    redirect('/training')
}

export async function auth(mode, prevState, formData){
    if(mode === 'login'){
        return login(prevState, formData)
    }

    return signup(prevState, formData)
}

export async function logout() {
    destroySession()
    redirect('/')
}