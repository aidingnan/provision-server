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
const { PEM, ASN1 } = require('@fidm/asn1')
const jwt = require('jwt-simple')
const devicePolicy = require('./devicePolicy')

const table = 'winas-cert'
const policyName = 'Policy_Device_Iot'
const defaultDomain = 'aws-cn'
// OID
const O = '2.5.4.10'
const CN = '2.5.4.3'
const OU = '2.5.4.11'
const SN = '2.5.4.5'

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
      this._Iot.detachPolicyAsync = Promise.promisify(this._Iot.detachPolicy).bind(this._Iot)
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

  get docClient() {
    if (!this._docClient) {
      this._docClient = new AWS.DynamoDB.DocumentClient(this.awsConfig)
      this._docClient.putAsync = Promise.promisify(this._docClient.put).bind(this._docClient)
      this._docClient.deleteAsync = Promise.promisify(this._docClient.delete).bind(this._docClient)
      this._docClient.getAsync = Promise.promisify(this._docClient.get).bind(this._docClient)
    }
    return this._docClient
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

  /*
  async getCertBySNAsync(sn, domain) {
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
  }*/
  
  async preparePolicyAsync(policyName) {
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

  async attachPolicyAsync(policyName, certificateArn) {
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

  async rollbackCertAsync(certId, certArn) {
    await this.iot.updateCertificateAsync({
      certificateId: certId,
      newStatus: 'INACTIVE'
    })
    try {
      await this.iot.detachPolicyAsync({
        target: certArn,
        policyName
      })
      await this.iot.deleteCertificate({ certificateId: certId })
    } catch(e) { // ignore error
      console.log(e)
    }
  }

  async getCertBySNAsync(sn, domain) {
    if (!domain) domain = defaultDomain
    if (!sn) throw Object.assign(new Error('sn not found'), { status: 400 })
    const params = {
      TableName: table,
      Key: {
          sn,
          domain
      }
    }
    let result = await this.docClient.getAsync(params)
    return result && result.Item
  }

  parseCSR(csr) {
    const pems = PEM.parse(csr)
    const asn1 = ASN1.fromDER(pems[0].body)
    const SEQUENCE = asn1.value && asn1.value.length && asn1.value[0]
    if (!SEQUENCE) return
    const OIDs = SEQUENCE.value && SEQUENCE.value.length > 1 && SEQUENCE.value[1]
    if (!OIDs || !OIDs.value || !OIDs.value.length) return
    const result = {}
    OIDs.value.forEach(x => {
      let items = x.value && x.value.length && x.value[0].value
      // OID  === 6
      if (!items || items.length != 2 || items[0].tag !== 6) return
      result[items[0].value] = items[1].value
    })
    if (!Object.getOwnPropertyNames(result).length) return
    return result
  }

  async registByCsr ({ sn, csr }, { code }) {
    let result = this.parseCSR(csr)
    if (!result || !result[OU] || !result[SN]) {
      throw Object.assign(new Error(' csr miss key property, ou || sn'), { code: 'ECSR', status: 400 })
    }
    let item = await this.getCertBySNAsync(result[SN], result[OU])
    if (item) return item // return exists result

    let data = await this.iot.createCertificateFromCsrAsync({
      certificateSigningRequest: csr,
      setAsActive: true
    })
    
    let { certificateId, certificatePem, certificateArn } = data

    
    await this.preparePolicyAsync(policyName)
    await this.attachPolicyAsync(policyName, certificateArn)
    
    // Get infomation in x509 pem
    const certInfo = x509.Certificate.fromPEM(certificatePem)
    const keyId = certInfo.subjectKeyIdentifier
    const subject = certInfo.subject

    if (!subject.serialName || subject.serialName !== sn) // sn
      throw Object.assign(new Error('sn mismatch'), { code: 'EMISMATCH', status: 400 })
    if (!subject.organizationalUnitName) // domain
      throw Object.assign(new Error('domain not found in csr`s OU'), { code: 'EDOMAIN', status: 400 })
    let connect = await this.pool.getConnectionAsync()
    Promise.promisifyAll(connect)

    const params = {
      TableName: table,
      Item: {
        certId: certificateId,
        sn: subject.serialName,
        domain: subject.organizationalUnitName,
        sub_cn: subject.commonName,
        sub_o: subject.organizationName,
        keyId,
        certPem: certificatePem,
        certArn: certificateArn,
        pcode: code
      }
    }

    await connect.beginTransactionAsync()
    try {
      // insert device info into device table
      await connect.queryAsync(`INSERT INTO device (sn, certId, keyId) VALUES (?,?,?) on duplicate key update certId='${certificateId}', keyId='${keyId}'`,
        [sn, certificateId, keyId])
      await this.docClient.putAsync(params)
      await connect.commitAsync()
    } catch(e) {
      await connect.rollbackAsync()
      await this.docClient.deleteAsync({
        TableName: table,
        Key: { certId: certificateId }
      })
      connect.release()
      await this.rollbackCertAsync(certificateId, certificateArn)
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
      return payload
    return false
  }
}

module.exports = AppService