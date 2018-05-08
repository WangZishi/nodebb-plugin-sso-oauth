// tslint:disable-next-line:no-implicit-dependencies
import * as n from 'nconf';

if (!module.parent) { throw new Error('Must use as a plugin.'); }

const nconf: typeof n = module.parent.require('nconf');
// const clientID: string = nconf.get('oauth2:id');
/**
 * OAuth Plugin
 */
class OAuth {

    private readonly constants: Constants = Object.freeze({
        type: '',
        name: '',
        oauth2: Object.freeze({
            authorizationURL: '',
            tokenURL: '',
            clientID: nconf.get('oauth2:id'),
            clientSecret: nconf.get('oauth2:secret'),
        }),
        userRoute: '',
    });

    public async getStrategy(strategies: IStrategy[]): Promise<IStrategy[]> {
        const passportOAuth = await import('passport-oauth2');
        passportOAuth.Strategy.prototype.userProfile = function () {
            // this._oauth.get();
        }
        return [];
    }

    public parseUserReturn(): void { return; }

    public login(): void { return; }

    public deleteUserData(): void { return; }
}

interface IStrategy {
    name: string;
    url: string;
    callbackURL: string;
    icon: string;
    scope: string[];
}

type Constants = Readonly<{
    // tslint:disable-next-line:no-reserved-keywords
    type: string;
    name: string;
    oauth2: Readonly<{
        authorizationURL: string;
        tokenURL: string;
        clientID: string;
        clientSecret: string;
    }>;
    userRoute: string;
}>;
