// import the cheribuildProject() step
@Library('ctsrd-jenkins-scripts') _

class GlobalVars { // "Groovy"
    public static boolean archiveArtifacts = false
}

def jobProperties = [
    rateLimitBuilds(throttle: [count: 2, durationName: 'hour', userBoost: true]),
    [$class: 'GithubProjectProperty', projectUrlStr: 'https://github.com/CTSRD-CHERI/qemu'],
    copyArtifactPermission('*'), // Downstream jobs need QEMU
]

// Don't archive binaries for pull requests and non-default branches:
def archiveBranches = ['qemu-cheri', 'dev']
if (!env.CHANGE_ID && archiveBranches.contains(env.BRANCH_NAME)) {
    GlobalVars.archiveArtifacts = true
    jobProperties.add(pipelineTriggers([triggers: [[$class: 'jenkins.triggers.ReverseBuildTrigger',
                                                    upstreamProjects: "BBL/cheri_purecap",
                                                    threshold: hudson.model.Result.SUCCESS]]]))
}

def paramsArray = []

// Add an OS selector for manual builds
def allConfigs = ["linux", "freebsd", "linux-debug"]
paramsArray.add(text(defaultValue: allConfigs.join('\n'),
        description: 'The configurations to build for (one per line)',
        name: 'Configs'))

jobProperties.add(parameters(paramsArray))

// Set the default job properties (work around properties() not being additive but replacing)
setDefaultJobProperties(jobProperties)

jobs = [:]

def extraBuildSteps(params, String os) {
    sh "rm -rf \$WORKSPACE/qemu-${os} && mv \$WORKSPACE/tarball/usr \$WORKSPACE/qemu-${os}"
    // Embed BBL binary (currently only needed when archiving, but could be used for build-time testing in future).
    copyArtifacts projectName: "BBL/cheri_purecap", filter: "bbl-riscv64cheri-virt-fw_jump.bin", target: "qemu-${os}/share/qemu", fingerprintArtifacts: true
}

def maybeArchiveArtifacts(params, String os) {
    if (GlobalVars.archiveArtifacts) {
        stage("Archiving artifacts") {
            // Add all the firmwares that are needed to boot CheriBSD
            def firmwareFiles = [
                "efi-pcnet.rom", "vgabios-cirrus.bin", // MIPS
                "bbl-riscv64cheri-virt-fw_jump.bin", // RISC-V
                "bios-256k.bin", "efi-virtio.rom", "vgabios-stdvga.bin", // x86_64
                "edk2-aarch64-code.fd"  // AArch64
            ].collect { "qemu-${os}/share/qemu/$it" }.join(', ')
            archiveArtifacts allowEmptyArchive: false, artifacts: "qemu-${os}/bin/qemu-system-*, qemu-${os}/bin/qemu-img, ${firmwareFiles}", fingerprint: true, onlyIfSuccessful: true
        }
    }
}

def addBootJobs(bootJobs, params, String qemuConfig, String architecture, String cheribsdBranch, String suffix="") {
    // For purecap architectures we boot both hybrid and purecap kernels.
    if (architecture.endsWith("-purecap")) {
        bootJobs["${architecture}-purecap-kernel${suffix} on ${qemuConfig}"] =
            { -> bootCheriBSD(params, qemuConfig, "${architecture}-purecap-kernel${suffix}", architecture,
                              'purecap', cheribsdBranch) }
        bootJobs["${architecture}-hybrid-kernel${suffix} on ${qemuConfig}"] =
            { -> bootCheriBSD(params, qemuConfig, "${architecture}-hybrid-kernel${suffix}", architecture,
                              'hybrid', cheribsdBranch) }
    } else {
        bootJobs["${architecture} on ${qemuConfig}"] =
            { -> bootCheriBSD(params, qemuConfig, "${architecture}${suffix}", architecture, null, cheribsdBranch) }
    }
}

def bootCheriBSDForAllArchitectures(params, String qemuConfig, boolean isDebug) {
    stage("Boot CheriBSD (${qemuConfig})") {
        bootJobs = [failFast: false]
        ["riscv64", "riscv64-purecap", "aarch64", "morello-purecap"].each { String architecture ->
            addBootJobs(bootJobs, params, qemuConfig, architecture, "main")
            if (!isDebug) {
                // For the non-ASAN build of QEMU we also boot the latest release
                addBootJobs(bootJobs, params, qemuConfig, architecture, "releng%252F22.12", "-latest-release")
            }
            def targetBranch = env.CHANGE_TARGET ? env.CHANGE_TARGET : env.BRANCH_NAME;
            if (targetBranch == 'dev') {
                addBootJobs(bootJobs, params, qemuConfig, architecture, "dev", "-dev")
            }
        }
        parallel bootJobs
    }
}

def bootCheriBSD(params, String qemuConfig, String stageSuffix, String archSuffix, String kernelABI, String cheribsdBranch="main") {
    try {
        def defaultKernelAbi = cheribsdInfo.getDefaultKernelAbi(cheribsdBranch)
        def extraCheribuildArgs = [
            "--cheribsd/default-kernel-abi=${defaultKernelAbi}"
        ]
        def compressedKernel = "artifacts-${archSuffix}/kernel.xz"
        if (kernelABI != null) {
            extraCheribuildArgs += ["--run-${archSuffix}/kernel-abi=${kernelABI}"]
            if (archSuffix.startsWith('riscv64') && kernelABI != defaultKernelAbi) {
                def kernelConfig = cheribsdInfo.getKernelConfig(archSuffix, kernelABI, cheribsdBranch)
                compressedKernel = "artifacts-${archSuffix}/kernel.${kernelConfig}.xz"
            }
        }
        def compressedDiskImage = "artifacts-${archSuffix}/cheribsd-${archSuffix}.img.xz"
        dir (stageSuffix) {
            sh "rm -rfv artifacts-${archSuffix}/cheribsd-*.img* artifacts-${archSuffix}/kernel*"
            copyArtifacts projectName: "CheriBSD-pipeline/${cheribsdBranch}", filter: "${compressedDiskImage}, ${compressedKernel}",
                         target: '.', fingerprintArtifacts: false, flatten: false, selector: lastSuccessful()
        }
        def testExtraArgs = [
                '--no-timestamped-test-subdir',
                '--no-keep-compressed-images',
                // Run a small subset of kyua tests to match the CheriBSD CI
                '--kyua-tests-files=/usr/tests/bin/cat/Kyuafile',
                "--test-output-dir=\$WORKSPACE/test-results/${stageSuffix}",
                "--disk-image=${stageSuffix}/${compressedDiskImage}",
                "--kernel=${stageSuffix}/${compressedKernel}",
        ]
        sh label: 'generate SSH key',
           script: 'test -e $WORKSPACE/id_ed25519 || ssh-keygen -t ed25519 -N \'\' -f $WORKSPACE/id_ed25519 < /dev/null'
        sh label: "Boot CheriBSD (${stageSuffix})", script: """
    rm -rf test-results/${stageSuffix} && mkdir -p test-results/${stageSuffix}
    ./cheribuild/jenkins-cheri-build.py --test run-${archSuffix} '--test-extra-args=${testExtraArgs.join(" ")}' \
        --test-ssh-key \$WORKSPACE/id_ed25519.pub ${extraCheribuildArgs.join(" ")} || echo Boot test failed
    """
        def summary = junitReturnCurrentSummary allowEmptyResults: false, keepLongStdio: true,
                                                testResults: "test-results/${stageSuffix}/test-results.xml"
        def testResultMessage = "Test summary: ${summary.totalCount}, Failures: ${summary.failCount}, Skipped: ${summary.skipCount}, Passed: ${summary.passCount}"
        echo("${stageSuffix}: ${testResultMessage}")
        if (summary.passCount == 0 || summary.totalCount == 0) {
            params.statusFailure("No tests successful?")
        } else if (summary.failCount != 0) {
            // Note: Junit set should have set stage/build status to unstable already, but we still need to set
            // the per-configuration status, since Jenkins doesn't have a build result for each parallel branch.
            params.statusUnstable("Unstable test results: ${testResultMessage}")
            // If there were test failures, we archive the JUnitXML file to simplify debugging
            archiveArtifacts allowEmptyArchive: true, artifacts: "test-results/${stageSuffix}/*.xml", onlyIfSuccessful: false
        }
    } finally {
        dir (stageSuffix) {
            deleteDir()
        }
    }
}

// Work around for https://issues.jenkins.io/browse/JENKINS-46941
// Jenkins appears to use the last selected manual override for automatically triggered builds.
// Therefore, only read the parameter value for manually-triggered builds.
def selectedConfigs = isManualBuild() && params.Configs != null ? params.Configs.split('\n') : allConfigs
echo("Selected Configs: ${selectedConfigs}")
selectedConfigs.each { config ->
    def os = config.split('-')[0]
    def nodeLabel = os
    if (os == 'linux') {
        // Build on the oldest supported Ubuntu version so the binaries also run there
        nodeLabel = "${nodeLabel}-baseline"
    }
    jobs[config] = { ->
        node(nodeLabel) {
            def extraQemuArgs = ''
            boolean isDebug = config.endsWith('-debug')
            if (isDebug) {
                extraQemuArgs = '"--qemu/configure-options=--enable-rvfi-dii --extra-cflags=-O2 --extra-cxxflags=-O2" --qemu/build-type=Debug'
            }
            def qemuResult = cheribuildProject(target: 'qemu', cpu: 'native', skipArtifacts: true,
                    nodeLabel: null,
                    extraArgs: "--without-sdk --install-prefix=/usr $extraQemuArgs",
                    runTests: true,
                    uniqueId: "qemu-build-${config}",
                    skipTarball: true,
                    afterBuild: { params ->
                        extraBuildSteps(params, os)
                        bootCheriBSDForAllArchitectures(params, config, isDebug)
                        // For Debug+ASAN we don't archive artifacts.
                        if (!isDebug) {
                            maybeArchiveArtifacts(params, os)
                        }
                    })

            // Run the generated Morello tests
            stage("Run Morello tests") {
                sh "qemu-${os}/bin/qemu-system-morello --version"
                dir('morello-generated-tests') {
                    cloneGitRepoWithReference(url: 'https://github.com/rems-project/morello-generated-tests.git',
                                              branch: 'main', credentialsId: 'ctsrd-jenkins-new-github-api-key')
                }
                sh """#!/usr/bin/env bash
set -xe
virtualenv -p python3 venv
source venv/bin/activate
pip install pytest-xdist
# The pytest.ini configuration ensures that pytest-xdist autodetects the number of CPUs used for running tests.
pytest qemu/tests/morello \
--morello-tests-dir=\$WORKSPACE/morello-generated-tests \
--qemu=\$WORKSPACE/qemu-${os}/bin/qemu-system-morello \
--junit-xml=\$WORKSPACE/morello-generated-tests-result.xml || echo "Some tests failed"
"""
                junit allowEmptyResults: false, keepLongStdio: true, testResults: 'morello-generated-tests-result.xml'
            }
            // Run the baremetal MIPS tests to check we didn't regress.
            if (os == 'linux') {
                cheribuildProject(target: 'cheritest-qemu', architecture: 'native',
                        customGitCheckoutDir: 'cheritest', scmOverride: gitRepoWithLocalReference(url: 'https://github.com/CTSRD-CHERI/cheritest.git'),
                        nodeLabel: null,
                        // Ensure that test failures don't prevent creation of the junit file
                        extraArgs: '--install-prefix=/ --cheritest-qemu/no-run-tests-with-build',
                        runTests: true,
                        // Set the status message on the QEMU repo not the cheritest one
                        gitHubStatusArgs: qemuResult.gitInfo,
                        sdkCompilerOnly: true, skipTarball: true,
                        uniqueId: "mips-baremetal-testsuite-${config}",
                        junitXmlFiles: 'cheritest/nosetests_qemu*.xml')
            }
        }
    }
}

boolean runParallel = true
echo("Running jobs in parallel: ${runParallel}")
if (runParallel) {
    jobs.failFast = false
    parallel jobs
} else {
    jobs.each { key, value ->
        echo("RUNNING ${key}")
        value()
    }
}
