import { Strategy } from 'passport-strategy'
import ldap from 'ldapjs'

export class LdapStrategy extends Strategy {
    name: string
    ldapUrl: string
    password: string
    verify: any
    binddn: string
    base: string
    filter: string

    constructor(options: any, verify: any) {
        super()
        if (!options) { throw new Error('LdapStrategy requires options') }
        if (typeof verify != 'function') { throw new TypeError('LdapStrategy requires a verify callback') }

        this.name = 'ldap'
        this.filter = options.filter
        this.base = options.base
        this.binddn = options.binddn
        this.password = options.password
        this.ldapUrl = options.ldapUrl
        this.verify = verify
    }

    authenticate(req: any) {
        const { username, password } = req.body
        if(!username || !password) {
            this.fail({ message: 'Missing credentials' }, 400)
        }
        const dn = this.binddn
        const pwd = this.password
        const base = this.base
        const filter = this. filter

        let client = ldap.createClient({url: [this.ldapUrl]})
        client.bind(dn, pwd, err => {
            if(err) {
                if(
                    err.name == 'InvalidCredentialsError' ||
                    err.name == 'NoSuchObjectError' ||
                    (typeof err == 'string' && `${err}`.match(/no such user/i))
                ) { return this.fail({ message: 'Invalid username/password'}, 401) }
                return this.error(err)
            }
            
            client.search(base, { filter }, (err, res) => {
                if (err) { this.fail({ err }, 401)}

                let items:any[]  = []
                res.on('searchEntry', entry => { items.push(entry.object) })
                res.on('error', err => this.fail({ err }, 401))
                res.on('end', result => {
                    const status  = result?.status
                    if(status != 0) { this.fail(`non-zero status from LDAP search: ${status}`, 401) }

                    switch (items.length) {
                        case 0: return this.fail(`No search entry, please check your configuration`, 401)
                        case 1: return this.verify(items[0], (err: any, user: any, info: any) => {
                            if(err) return this.error(err)
                            if(!user) return this.fail({info}, 401)
                            return this.success(user, info)
                        })
                        default:
                            return this.fail(`Unexpected number of matches (${items.length}) for ${username} username`, 401)
                    }
                })
            })
        })
    }

}





