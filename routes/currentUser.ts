/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import * as challengeUtils from '../lib/challengeUtils'
import { type Request, type Response } from 'express'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'

export function retrieveLoggedInUser () {
  return (req: Request, res: Response) => {
    let user
    let response: any
    try {
      if (security.verify(req.cookies.token)) {
        user = security.authenticatedUsers.get(req.cookies.token)
        const hasShowSensitive = typeof req.query?.showSensitive !== 'undefined'
        const rawShowSensitive = req.query?.showSensitive
        const showHash = hasShowSensitive && (String(rawShowSensitive) === 'true' || String(rawShowSensitive) === '1')
        const baseUser = {
          id: user?.data?.id,
          email: user?.data?.email,
          lastLoginIp: user?.data?.lastLoginIp,
          profileImage: user?.data?.profileImage
        }
        response = { user: baseUser }
        if (user?.data != null) {
          const stored = (user as any).data.password
          if (hasShowSensitive) {
            response.user.passwordHash = showHash ? stored : (stored ? String(stored).replace(/./g, '*') : undefined)
          }
        }
      } else {
        response = { user: { id: undefined, email: undefined, lastLoginIp: undefined, profileImage: undefined } }
      }
    } catch (err) {
      response = { user: { id: undefined, email: undefined, lastLoginIp: undefined, profileImage: undefined } }
    }
    if (req.query.callback === undefined) {
      res.json(response)
    } else {
      challengeUtils.solveIf(challenges.emailLeakChallenge, () => { return true })
      res.jsonp(response)
    }
  }
}
