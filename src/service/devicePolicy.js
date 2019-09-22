/*
 * Filename: /home/jackyang/factory/src/service/devicePolicy.js
 * Path: /home/jackyang/factory
 * Created Date: Monday, October 8th 2018, 1:52:08 pm
 * Author: JackYang
 * 
 * Copyright (c) 2018 Wisnuc Inc
 */

/* eslint-disable */
module.exports = {
  Version: "2012-10-17",
  Statement: [
    {
      Effect: "Allow",
      Action: [
        "iot:Connect"
      ],
      Resource: [
        "arn:aws-cn:iot:cn-north-1:569395011106:client/${iot:Connection.Thing.ThingName}"
      ]
    },
    {
      Effect: "Allow",
      Action: [
        "iot:Publish"
      ],
      Resource: [
        "arn:aws-cn:iot:cn-north-1:569395011106:topic/device/${iot:Connection.Thing.ThingName}/*"
      ]
    },
    {
      Effect: "Allow",
      Action: [
        "iot:Subscribe"
      ],
      Resource: [
        "arn:aws-cn:iot:cn-north-1:569395011106:topicfilter/cloud/${iot:Connection.Thing.ThingName}/*"
      ]
    },
    {
      Effect: "Allow",
      Action: [
        "iot:Receive"
      ],
      Resource: "*"
    },
    {
      Effect: "Allow",
      Action: [
        "iot:UpdateThing",
        "iot:ListThings"
      ],
      Resource: "*"
    }
  ]
}