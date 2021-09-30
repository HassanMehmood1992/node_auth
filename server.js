require('dotenv').config()

const express = require('express')
const jwt = require('jsonwebtoken')
const app = express()

app.use(express.json())

const posts = [
    {
        name: 'Hassan',
        post: 'Post 1'
    },
    {
        name: 'James',
        post: 'Post 2'
    }
]

app.get('/posts', authenticateToken, (req, res) => {
    res.json(posts.filter(post => post.name === req.user.name))
})

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if (token == null) return res.sendStatus(401)
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403)
        req.user = user
        next()
    })
}
app.listen(3000)