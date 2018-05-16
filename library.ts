/**
 *
 */

// tslint:disable-next-line:no-implicit-dependencies
import { Request } from 'express';
// tslint:disable-next-line:no-implicit-dependencies
import * as n from 'nconf';
// tslint:disable-next-line:no-implicit-dependencies
import * as p from 'passport';
import { InternalOAuthError, Strategy, StrategyOptionsWithRequest } from 'passport-oauth2';
import { URL } from 'url';
import { callbackify, promisify } from 'util';

if (!module.parent) { throw new Error('Must use as a plugin.'); }

// tslint:disable-next-line:variable-name
const User = module.parent.require('./user');
const nconf: typeof n = module.parent.require('nconf');
const passport: typeof p = module.parent.require('passport');
const db = module.parent.require('../src/database');
const authenticationCtrl = module.parent.require('./controllers/authentication');
const winston = module.parent.require('winston');

const constants: Constants = Object.freeze({
    type: 'oauth2',
    name: 'sheencity',
    oauth2: Object.freeze({
        authorizationURL: nconf.get('oauth2:authURL'),
        tokenURL: nconf.get('oauth2:tokenURL'),
        clientID: nconf.get('oauth2:id'),
        clientSecret: nconf.get('oauth2:secret'),
    }),
    userRoute: nconf.get('oauth2:userURL'),
});

function parseUser(data: IData): IProfile {
    const profile: IProfile = {
        id: data.value.id,
        displayName: data.value.username,
        emails: [],
    };

    if (data.value.email) {
        profile.emails.push({ value: data.value.email });
    }

    return profile;
}

class OAuth2Strategy extends Strategy {
    public userProfile(accessToken: string, done: (err: Error | null, profile?: IProfile) => void): void {
        const id = JSON.parse(Buffer.from(accessToken.split('.')[1], 'base64').toString()).id;
        // tslint:disable-next-line:typedef
        const callback = (err: object, body: object, res: object) => {
            if (err) { return done(new InternalOAuthError('failed to fetch user profile', err)); }

            try {
                const json: IData = JSON.parse(body.toString());

                const profile = parseUser(json);

                profile.provider = constants.name;

                done(null, profile);
            } catch (e) {
                done(e);
            }

        };
        this._oauth2.setAuthMethod('Bearer');
        this._oauth2.useAuthorizationHeaderforGET(true);

        // tslint:disable-next-line:prefer-type-cast no-any
        this._oauth2.get(`constants.userRoute/${id}`, accessToken, callback as any);
    }
}

async function verifyFunctionWithRequest(
    req: Request,
    toekn: string,
    secret: string,
    profile: IProfile,
): Promise<{ uid: string }> {
    const user = await login({
        oAuthid: profile.id,
        handle: profile.displayName,
        email: profile.emails[0].value,
        isAdmin: false,
    });

    authenticationCtrl.onSuccessfulLogin(req, user.uid);

    return user;
}

async function login(payload: ILoginPayload): Promise<{ uid: string }> {
    let uid: string | null = await getUidByOAuthid(payload.oAuthid);

    if (!uid) {
        uid = await promisify(User.create)({
            username: payload.handle,
            email: payload.email,
        });

        User.setUserField(uid, `${constants.name}Id`, payload.oAuthid);
        db.setObjectField(`${constants.name}Id:uid`, payload.oAuthid, uid);
    }

    if (!uid) { throw new Error('User login failed.'); }

    return { uid };
}

function getUidByOAuthid(oAuthid: string): Promise<string> {
    return promisify(db.getUidByOAuthid)(`${constants.name}Id:uid`, oAuthid);
}

async function getStrategy(strategies: IStrategy[]): Promise<IStrategy[]> {
    const passportOAuth = await import('passport-oauth2');
    const url = new URL(`${nconf.get('url')}/auth/${constants.name}/callback`);
    url.protocol = 'https:';

    const opt: StrategyOptionsWithRequest = {
        ...constants.oauth2,
        callbackURL: url.href,
        passReqToCallback: true,
    };

    passport.use(constants.name, new OAuth2Strategy(opt, callbackify(verifyFunctionWithRequest)));

    strategies.push({
        name: constants.name,
        url: `/auth/${constants.name}`,
        callbackURL: `/auth/${constants.name}/callback`,
        icon: 'fa-check-square',
        scope: [],
    });

    return strategies;
}

async function deleteUserData(user: { uid: string }): Promise<{ uid: string }> {

    try {
        const oAuthIdDelete = await promisify(User.getUserField)(user.uid, `${constants.name}Id`);
        await promisify(db.deleteObjectField)(`${constants.name}Id:uid`, oAuthIdDelete);
    } catch (err) {
        winston.error(`[sso-oauth] Could not remove OAuthId data for uid ${user.uid}. Error: ${err}`);
        throw err;
    }

    return user;
}

module.exports = {
    getStrategy: callbackify(getStrategy),
    deleteUserData: callbackify(deleteUserData),
};

interface IStrategy {
    name: string;
    url: string;
    callbackURL: string;
    icon: string;
    scope: string[];
}

interface IData {
    value: {
        id: string;
        email: string | null;
        username: string;
    };
}

interface ILoginPayload {
    oAuthid: string;
    handle: string;
    email: string;
    isAdmin: boolean;
}

interface IProfile {
    id: string;
    displayName: string;
    emails: { value: string }[];
    provider?: string;
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
