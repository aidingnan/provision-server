/*
 * Filename: /home/jackyang/factory/src/service/index.js
 * Path: /home/jackyang/factory
 * Created Date: Friday, September 28th 2018, 5:21:58 pm
 * Author: JackYang
 * 
 * Copyright (c) 2018 Wisnuc Inc
 */

const AWS = require('aws-sdk')
const Promise = require('bluebird')
const mysql = require('mysql')
const x509 = require('@fidm/x509')
const jwt = require('jwt-simple')

const devicePolicy = require('./devicePolicy')

class AppService {
  constructor (config) {
    this.conf = config
    this.awsConfig = new AWS.Config()
    this.awsConfig.update({
      region: config.iot.region
    })

    this.AppSecret = 'abccaccb'
  }

  get iot() {
    if (!this._Iot) {
      this._Iot = new AWS.Iot(this.awsConfig)
      this._Iot.createCertificateFromCsrAsync = Promise.promisify(this._Iot.createCertificateFromCsr).bind(this._Iot)
      this._Iot.attachPrincipalPolicyAsync = Promise.promisify(this._Iot.attachPrincipalPolicy).bind(this._Iot)
      this._Iot.createPolicyAsync = Promise.promisify(this._Iot.createPolicy).bind(this._Iot)
      this._Iot.attachThingPrincipalAsync = Promise.promisify(this._Iot.attachThingPrincipal).bind(this._Iot)
      this._Iot.deleteCertificateAsync = Promise.promisify(this._Iot.deleteCertificate).bind(this._Iot)
      this._Iot.updateCertificateAsync = Promise.promisify(this._Iot.updateCertificate).bind(this._Iot)
      this._Iot.describeCertificateAsync = Promise.promisify(this._Iot.describeCertificate).bind(this._Iot)
    }
    return this._Iot
  }

  get pool() {
    if (!this._pool) {
      let dbConf = process.env.NODE_ENV === 'test' ? this.conf['rds-test'] : this.conf.rds
      this._pool = mysql.createPool({
        connectionLimit: 20,
        host: dbConf.host,
        user: dbConf.user,
        password: dbConf.password,
        database: dbConf.dbname
      })
      Promise.promisifyAll(this._pool)
    }
    return this._pool
  }

  destroy () {
    if (this._pool)
      this._pool.end(err => console.log(err))
  }

  certByKeyId (keyId, callback) {
    this.pool.getConnection((err, conn) => {
      if (err) return callback(err)
      conn.query(`select * from deviceCert where keyId = '${ keyId }'`, (err, results) => {
        conn.release()
        if (err) return callback(err)
        if (!results.length) return callback(Object.assign(new Error('not found'), { status: 404 }))
        return callback(null, results[0])
      })
    })
  }

  async getCertBySNAsync(sn) {
    // get connection
    let connect = await this.pool.getConnectionAsync()
    Promise.promisifyAll(connect)
    try {
      // query if exist
      let results = await connect.queryAsync(`select * from device where sn = '${ sn }'`)
      if (results.length) {
        let certificateId = results[0].certId
        let desc = await this.iot.describeCertificateAsync({ certificateId })
        if (desc && desc.certificateDescription) {
          return desc.certificateDescription
        }
      }
    } finally {
      connect.release()
    }
  }
  
  async preparePolicy(policyName) {
    // create policy
    try {
      await this.iot.createPolicyAsync({ policyDocument: JSON.stringify(devicePolicy), policyName: policyName })
    } catch(e) {
      //Ignore if the policy already exists
      if (!e.code || e.code !== 'ResourceAlreadyExistsException') {
        e.status = 500
        throw e
      }
    }
  }

  async attachPolicy(policyName, certificateArn) {
    // Attach the policy to the certificate
    try {
      await this.iot.attachPrincipalPolicyAsync({ policyName: policyName, principal: certificateArn })
    } catch(e) {
      //Ignore if the policy already exists
      if (!e.code || e.code !== 'ResourceAlreadyExistsException') {
        e.status = 500
        throw e
      }
    }
  }

  /* eslint-disable */
  async registByCsr ({ sn, reversion, csr, type }) {
    let desc = await this.getCertBySNAsync(sn)
    if (desc) {
      if (desc.status !== "ACTIVE")
        await this.iot.updateCertificateAsync({certificateId: desc.certificateId, newStatus:"ACTIVE"})
      return {
        certPem: desc.certificatePem,
        certId: desc.certificateId,
        certArn: desc.certificateArn
      }
    }

    let data = await this.iot.createCertificateFromCsrAsync({
      certificateSigningRequest: csr,
      setAsActive: true
    })
    
    let { certificateId, certificatePem, certificateArn } = data

    let policyName = 'Policy_Device_Iot'
    await this.preparePolicy(policyName)
    await this.attachPolicy(attachPolicy, certificateArn)
    
    if (type === 'test') {
      try {
        await this.iot.attachThingPrincipalAsync({
          thingName: 'testEnv',
          principal: certificateArn
        })
      } catch (e) {
        if (!e.code || e.code !== 'ResourceAlreadyExistsException') {
          e.status = 500
          throw e
        }
      }
    }

    // Get infomation in x509 pem
    let certInfo = x509.Certificate.fromPEM(certificatePem)
    let keyId = certInfo.subjectKeyIdentifier
    let authkeyId = certInfo.authorityKeyIdentifier

    let sub_o = certInfo.subject.organizationName || null
    let sub_cn = certInfo.subject.commonName || null
    let iss_o = certInfo.issuer.organizationName || null
    let iss_cn = certInfo.issuer.commonName || null
    let iss_ou = certInfo.issuer.organizationalUnitName || null
    
    let certSN = certInfo.serialNumber
    let connect = await this.pool.getConnectionAsync()
    Promise.promisifyAll(connect)

    await connect.beginTransactionAsync()
    try {
      // insert device info into device table
      await connect.queryAsync(`INSERT INTO device (sn, certId, keyId) VALUES (?,?,?) on duplicate key update certId='${certificateId}', keyId='${keyId}'`,
        [sn, certificateId, keyId])
      // insert certInfo into deviceCert
      await connect.queryAsync(`INSERT INTO deviceCert (keyId, sub_o, sub_cn, iss_o, iss_cn, iss_ou, authkeyId, certSn) VALUES (?,?,?,?,?,?,?,?) on duplicate key update keyId='${keyId}'`,
        [keyId, sub_o, sub_cn, iss_o, iss_cn, iss_ou, authkeyId, certSN])

      await connect.commitAsync()      
    } catch(e) {
      await connect.rollbackAsync()
      connect.release()
      throw e
    }
    connect.release()

    return {
      certPem: certificatePem,
      certId: certificateId,
      certArn: certificateArn
    }
  }

  async getCodeInfoAsync (code) {
    // get connection
    let connect = await this.pool.getConnectionAsync()
    Promise.promisifyAll(connect)
    try {
      // query if exist
      let results = await connect.queryAsync(`select UNIX_TIMESTAMP(createdAt)  as createdAt, UNIX_TIMESTAMP(expiredAt) as expiredAt from provisionCode where code = '${ code }'`)
      if (results.length) {
        return results[0]
      } else {
        throw new Error(`${code} not found`)
      }
    } finally {
      connect.release()
    }
  }

  async getTokenAsync (code) {
    if (typeof code != 'string' || !code.length) {
      throw Object.assign(new Error('code not found'), { status: 400 })
    }

    let info = await this.getCodeInfoAsync(code)
    if (new Date().getTime() / 1000 > info.expiredAt) {
      throw Object.assign(new Error('code already expired'), { status: 400 })
    }

    return jwt.encode({
      code,
      expiredAt: info.expiredAt,
      createdAt: info.createdAt
    }, this.AppSecret)
  }

  async verifyTokenAsync(token) {
    let payload = jwt.decode(token, this.AppSecret)
    if (payload.expiredAt > new Date().getTime() / 1000)
      return true
    return false
  }

}

module.exports = AppService