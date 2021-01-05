require("dotenv").config();
const express = require("express");
const morgan = require("morgan");
const mysql = require("mysql2/promise");
const jwt = require('jsonwebtoken')
const cors = require('cors')
//Passport Core
const passport = require("passport");
//Passport Stratgy
const LocalStrategy = require("passport-local").Strategy;


const authMiddleWare = (passport) => {
    return(req,res,next) => {
       
        passport.authenticate('local', 
        (err,user,info) => {
			//attached user to the request obj
            req.user = user 
            if((null != err)||(!user)) {
                res.status(401)
                res.type('application/json')
                res.json({error:err})
                return
            }
            next()
        }
        ) (req,res,next)
    }
}
const TOKEN_SECRET = process.env.TOKEN_SECRET ||'abcd1234'
//configure passport with a strategy
const pool = mysql.createPool({
	host: process.env.MYSQL_SERVER,
	port: process.env.MYSQL_SVR_PORT,
	user: process.env.MYSQL_USERNAME,
	password: process.env.MYSQL_PASSWORD,
	database: process.env.MYSQL_SCHEMA,
	connectionLimit: process.env.MYSQL_CON_LIMIT,
});
const SQL_AUTH =
    "select user_id from paf2020.user where user_id = ? and password = sha1(?)";

    const localStrategyAuth = authMiddleWare(passport)
passport.use(
	new LocalStrategy(
		{
			usernameField: "username",
			passwordField: "password",
			passReqToCallback: true,
		},
		async (req, user, password, done) => {
			const conn = await pool.getConnection();
			console.log(user, password);
			try {
				let authResult = await conn.query(SQL_AUTH, [user, password]);
				console.log("length", authResult[0].length);
				if (authResult[0].length == 1) {
					done(
						null,
						//info about the user for the application to use
						{
							username: authResult[0][0].user_id,
							loginTime: new Date().toString(),
							security: 2,
						}
					);
					return;
				} else {
					done("Incorrect username and password", false);
				}
			} catch (e) {
				console.log(e);
			} finally {
				conn.release();
			}
		}
	)
);

const app = express();

app.use(morgan("combined"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
//initialise passport after json and formurl
app.use(passport.initialize());

const PORT =
	parseInt(process.argv[2]) || parseInt(process.env.APP_PORT) || 3000;

app.post(
	"/login",
    //passport.authenticate("local", { session: false }),
    //custom authentication and callback to account for 401 status
    localStrategyAuth,
	// (req, res, next) => {

	// 	const f = passport.authenticate("local", (err, user, info)  => {
	// 		if (null != err) {
	// 			res.status(401);
	// 			res.json({ error: err });
	// 			return;
	// 		}
	// 		next();
    //     })
    //     f(req,res,next);
	// },
	(req, res) => {
		//do something
		console.log(req.user);
		const timestamp = (new Date()).getTime() / 1000
        const token = jwt.sign({
            sub: req.user.username,
            iss:'myapp',
			iat: timestamp,
			//expires in 20s
			exp: timestamp + 20,
			data: {user: req.user.username, loginTime: (new Date()).toString()  }
        }, TOKEN_SECRET)

		//generate JWT token
		res.status(200);
		res.type("application/json");
		res.json({ message: ` Login is at ${new Date()}`, token });
	}
);

app.get('/protected/secret',
(req,res,next) => {
	//check if the req has authorization header 
	const auth = req.get('Authorization')
	if(null == auth) {
		res.status(403)
		res.json({message: 'Cannot access'})
		return
	}
	console.log(auth)
	//Bearer authorization Bearer <token>
	const terms = auth.split(' ') //split between the space
	if ((terms.length != 2) || (terms[0] != 'Bearer')) {
		res.status(403)
		res.json({message: 'Cannot access'})
		return
	}

	const token = terms[1]
	console.log(token)
	try{
		const verified = jwt.verify(token, TOKEN_SECRET)
		console.log("verified", verified)
		req.token = verified
		next()
	}catch(e){
		res.status(403)
		res.json({message: 'Incorrect token', error: e})
		return
	}
},
(req,res)=> {
	res.status(200)
	res.json({meaning_of_life:42})
})
pool.getConnection()
	.then((conn) => {
		conn.ping()
		console.log("pinged");
		app.listen(PORT, () => {
			console.log(`${PORT} started`);
		});
		return conn;
	})
	.then((conn) => conn.release());
