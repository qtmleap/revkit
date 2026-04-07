import Orion
import NetflixSSLBypassC
import UIKit
import OSLog

private let logger = Logger(subsystem: "dev.tkgstrator.charon", category: "tweak")

class AppDelegateHook: ClassHook<NSObject> {
    typealias TargetType = NSObject

    static var targetName: String { "AppDelegate" }

    func applicationDidBecomeActive(_ application: UIApplication) {
        logger.info("[NFXBypass] AppDelegate didBecomeActive")
        orig.applicationDidBecomeActive(application)
    }

    func applicationWillResignActive(_ application: UIApplication) {
        logger.info("[NFXBypass] AppDelegate willResignActive")
        orig.applicationWillResignActive(application)
    }

    func applicationDidEnterBackground(_ application: UIApplication) {
        logger.info("[NFXBypass] AppDelegate didEnterBackground")
        orig.applicationDidEnterBackground(application)
    }
}

class ViewControllerHook: ClassHook<UIViewController> {
    func viewDidAppear(_ animated: Bool) {
        let className = String(describing: type(of: target))
        logger.info("[NFXBypass] viewDidAppear: \(className, privacy: .public)")
        orig.viewDidAppear(animated)
    }
}
