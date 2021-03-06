"use strict";
/**
 *
 */
var __extends = (this && this.__extends) || (function () {
    var extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
var __assign = (this && this.__assign) || Object.assign || function(t) {
    for (var s, i = 1, n = arguments.length; i < n; i++) {
        s = arguments[i];
        for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
            t[p] = s[p];
    }
    return t;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = y[op[0] & 2 ? "return" : op[0] ? "throw" : "next"]) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [0, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
var passport_oauth2_1 = require("passport-oauth2");
var url_1 = require("url");
var util_1 = require("util");
if (!module.parent) {
    throw new Error('Must use as a plugin.');
}
// tslint:disable-next-line:variable-name
var User = module.parent.require('./user');
var nconf = module.parent.require('nconf');
var passport = module.parent.require('passport');
var db = module.parent.require('../src/database');
var authenticationCtrl = module.parent.require('./controllers/authentication');
var winston = module.parent.require('winston');
var constants = Object.freeze({
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
function parseUser(data) {
    // tslint:disable-next-line:no-unnecessary-local-variable
    var profile = {
        id: data.value.id,
        displayName: data.value.username,
        emails: [{ value: data.value.email }],
    };
    // if (data.value.email) {
    //     profile.emails.push({ value: data.value.email });
    // }
    return profile;
}
var OAuth2Strategy = /** @class */ (function (_super) {
    __extends(OAuth2Strategy, _super);
    function OAuth2Strategy() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    OAuth2Strategy.prototype.userProfile = function (accessToken, done) {
        var id = JSON.parse(Buffer.from(accessToken.split('.')[1], 'base64').toString()).id;
        // tslint:disable-next-line:typedef
        var callback = function (err, body, res) {
            if (err) {
                return done(new passport_oauth2_1.InternalOAuthError('failed to fetch user profile', err));
            }
            try {
                var json = JSON.parse(body.toString());
                var profile = parseUser(json);
                profile.provider = constants.name;
                done(null, profile);
            }
            catch (e) {
                done(e);
            }
        };
        this._oauth2.setAuthMethod('Bearer');
        this._oauth2.useAuthorizationHeaderforGET(true);
        // tslint:disable-next-line:prefer-type-cast no-any
        this._oauth2.get(constants.userRoute + "/" + id, accessToken, callback);
    };
    return OAuth2Strategy;
}(passport_oauth2_1.Strategy));
function verifyFunctionWithRequest(req, toekn, secret, profile) {
    return __awaiter(this, void 0, void 0, function () {
        var user;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, login({
                        oAuthid: profile.id,
                        handle: profile.displayName,
                        email: profile.emails[0].value,
                        isAdmin: false,
                    })];
                case 1:
                    user = _a.sent();
                    authenticationCtrl.onSuccessfulLogin(req, user.uid);
                    return [2 /*return*/, user];
            }
        });
    });
}
function login(payload) {
    return __awaiter(this, void 0, void 0, function () {
        var uid, user;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, getUidByOAuthid(payload.oAuthid)];
                case 1:
                    uid = _a.sent();
                    if (!!uid) return [3 /*break*/, 3];
                    user = { username: payload.handle };
                    if (payload.email) {
                        user.email = payload.email;
                    }
                    return [4 /*yield*/, util_1.promisify(User.create)(user)];
                case 2:
                    uid = _a.sent();
                    User.setUserField(uid, constants.name + "Id", payload.oAuthid);
                    db.setObjectField(constants.name + "Id:uid", payload.oAuthid, uid);
                    _a.label = 3;
                case 3:
                    if (!uid) {
                        throw new Error('User login failed.');
                    }
                    return [2 /*return*/, { uid: uid }];
            }
        });
    });
}
function getUidByOAuthid(oAuthid) {
    return util_1.promisify(db.getObjectField)(constants.name + "Id:uid", oAuthid);
}
function getStrategy(strategies) {
    return __awaiter(this, void 0, void 0, function () {
        var passportOAuth, url, opt;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, Promise.resolve().then(function () { return __importStar(require('passport-oauth2')); })];
                case 1:
                    passportOAuth = _a.sent();
                    url = new url_1.URL(nconf.get('url') + "/auth/" + constants.name + "/callback");
                    url.protocol = 'https:';
                    opt = __assign({}, constants.oauth2, { callbackURL: url.href, passReqToCallback: true });
                    passport.use(constants.name, new OAuth2Strategy(opt, util_1.callbackify(verifyFunctionWithRequest)));
                    strategies.push({
                        name: constants.name,
                        url: "/auth/" + constants.name,
                        callbackURL: "/auth/" + constants.name + "/callback",
                        icon: 'fa-check-square',
                        scope: [],
                    });
                    return [2 /*return*/, strategies];
            }
        });
    });
}
function deleteUserData(user) {
    return __awaiter(this, void 0, void 0, function () {
        var oAuthIdDelete, err_1;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    _a.trys.push([0, 3, , 4]);
                    return [4 /*yield*/, util_1.promisify(User.getUserField)(user.uid, constants.name + "Id")];
                case 1:
                    oAuthIdDelete = _a.sent();
                    return [4 /*yield*/, util_1.promisify(db.deleteObjectField)(constants.name + "Id:uid", oAuthIdDelete)];
                case 2:
                    _a.sent();
                    return [3 /*break*/, 4];
                case 3:
                    err_1 = _a.sent();
                    winston.error("[sso-oauth] Could not remove OAuthId data for uid " + user.uid + ". Error: " + err_1);
                    throw err_1;
                case 4: return [2 /*return*/, user];
            }
        });
    });
}
module.exports = {
    getStrategy: util_1.callbackify(getStrategy),
    deleteUserData: util_1.callbackify(deleteUserData),
};
