
buildMvn {
  publishModDescriptor = 'yes'
  publishAPI = 'no'
  mvnDeploy = 'yes'
  doKubeDeploy = true

  doDocker = {
    buildJavaDocker {
      publishMaster = 'yes'
      healthChk = 'no'
    }
  }
}
