import initStoryshots from '@storybook/addon-storyshots';
import { imageSnapshot, Context } from '@storybook/addon-storyshots-puppeteer';
import { Browser, BrowserType, chromium, webkit, firefox, devices } from 'playwright'
import path from 'path'

// deviceName: refs https://github.com/microsoft/playwright/blob/v1.19.0/packages/playwright-core/types/types.d.ts#L15739
function initBrowserStoryshots(key: string, deviceName: string, browserType: BrowserType) {
  let browser: Browser;
  afterAll(() => {
    return browser.close();
  });

  // MEMO: puppeteerパッケージを入れているとここで型エラーになる
  const getCustomBrowser = async () => {
    browser = await browserType.launch()
    const context = await browser.newContext(devices[deviceName])
    return context
  }

  const getMatchOptions = (options: {context: Context, url: string}) => {
    const { kind, story } = options.context

    const dir = path.resolve(__dirname, '__image_snapshots__', key, kind)
    const name = story.replaceAll(/\s/g, '')

    return {
      customSnapshotsDir: path.resolve(dir),
      customSnapshotIdentifier: name,
    }
  }

  initStoryshots({
    test: imageSnapshot({
      storybookUrl: `file://${path.resolve(__dirname, '../storybook-static')}`,
      getCustomBrowser,
      getMatchOptions,
    })
  });
}

initBrowserStoryshots('Desktop-firefox', "Desktop Firefox", firefox)
initBrowserStoryshots('Pixel5-chrome', "Pixel 5", chromium)
initBrowserStoryshots('iPhone13-safari', "iPhone 13", webkit)
