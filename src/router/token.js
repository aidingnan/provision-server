/*
 * Filename: /home/jackyang/Documents/provisioning-server/src/router/token.js
 * Path: /home/jackyang/Documents/provisioning-server
 * Created Date: Thursday, October 11th 2018, 1:52:19 pm
 * Author: JackYang
 * 
 * Copyright (c) 2018 Wisnuc Inc
 */

const Router = require('express').Router

module.exports = (service) => {
  const router = Router()

  router.get('/', (req, res) => {
    let key = req.query.key
    if (!key) return res.status(401).end()
    service.getTokenAsync(key)
      .then(token => {
        res.success({
          type: 'JWT',
          token,
        })
      })
      .catch(e => res.error(e))
  })

  return router
}