require('dotenv').config()

const express = require('express')
const jwt = require('jsonwebtoken')
const app = express()

app.use(express.json())

// for demo this can be in db as it will reset on server start
let validRefreshTokens = []

app.post('/token', (req, res) => {
    const refreshToken = req.body.token

    if(refreshToken == null) return res.sendStatus(401)
    if(!validRefreshTokens.includes(refreshToken)) return res.sendStatus(403)
    // store this token to a radis cache / mongo DB / to main a session / e.g block a vehicle
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if(err)return res.sendStatus(403)
        // just get name here as its a verify so it has additional info such as  issuer name and validation and timestamps etc
        const accessToken = generateAccessToken({name: user.name})
        res.json({accessToken:accessToken})
    })
})

app.delete('/logout', (req,res)=> {
    validRefreshTokens = validRefreshTokens.filter(token => token !== req.body.token)
    res.sendStatus(204)
})
app.post('/login', (req, res) => {
    const username = req.body.username
    const user = {
        name: username
    }
    const accessToken = generateAccessToken(user)
    const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)
    validRefreshTokens.push(refreshToken)
    res.json({accessToken:accessToken, refreshToken:refreshToken})
})

function generateAccessToken (user)
{
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '35s'})
}
app.listen(4000)